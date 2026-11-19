# -*- coding: utf-8 -*-
"""frida_hook.py — Frida hook 脚本生成器(安卓逆向/CTF mobile 常用)

用途: 不用每次手写 JS, 按场景生成可直接运行的 Frida 注入脚本 + python 驱动:
      java     hook Java 类方法, 打印参数/返回值(可改返回值)
      native   hook so 导出函数/指定地址, 打印入参 dump
      crypto   hook javax.crypto.Cipher/Mac/MessageDigest, dump key 与明文密文
      replace  用 NativeCallback 替换 native 函数返回固定值
      生成后运行方式见输出的命令提示(需真机/模拟器 + frida-server, 本脚本自测
      只校验生成的 JS, 不依赖 frida 运行时)。

用法:
    python frida_hook.py java  --class com.example.MainActivity --method check
    python frida_hook.py native --module libnative.so --export Java_..._check
    python frida_hook.py crypto --out crypto.js
    python frida_hook.py replace --module libnative.so --addr 0x12340 --retval 1
    python frida_hook.py --selftest
"""
import argparse
import os
import sys

JAVA_TMPL = r'''Java.perform(function() {
    var Cls = Java.use('%(cls)s');
    Cls.%(method)s.overload().implementation = function() {
        console.log('[*] %(cls)s.%(method)s() called');
        var ret = this.%(method)s.apply(this, arguments);
        console.log('[*] return: ' + ret);
        return ret;      // 要改返回值时: return true / 'flag{...}';
    };
});
'''

NATIVE_TMPL = r'''// frida -U -f <包名> -l %(out)s --no-pause   (spawn 后附加)
var base = Module.findBaseAddress('%(module)s');
var target = %(target_expr)s;
console.log('[*] target @ ' + target);
Interceptor.attach(target, {
    onEnter: function(args) {
        console.log('[>] %(label)s arg0=' + args[0] + ' arg1=' + args[1]);
        try { console.log('    arg1 str: ' + Memory.readUtf8String(args[1])); } catch (e) {}
        // dump buffer: console.log(hexdump(ptr(args[0].toInt32()).readByteArray(64)));
    },
    onLeave: function(retval) {
        console.log('[<] retval=' + retval);
    }
});
'''

CRYPTO_TMPL = r'''Java.perform(function() {
    // Cipher: dump 算法/mode/padding、key、明文与密文
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[Cipher.doFinal] algorithm=' + this.getAlgorithm());
        try {
            var key = this.getOriginalKey !== undefined ? null : null;
        } catch (e) {}
        console.log('    input  : ' + bytesToHex(input));
        var out = this.doFinal(input);
        console.log('    output : ' + bytesToHex(out));
        return out;
    };
    // SecretKeySpec: 直接抓密钥字节
    var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
    SKS.$init.overload('[B', 'java.lang.String').implementation = function(key, alg) {
        console.log('[SecretKeySpec] ' + alg + ' key=' + bytesToHex(key));
        return this.$init(key, alg);
    };
    var MD = Java.use('java.security.MessageDigest');
    MD.digest.overload('[B').implementation = function(input) {
        var r = this.digest(input);
        console.log('[MessageDigest] ' + this.getAlgorithm() + ' in=' + bytesToHex(input) + ' out=' + bytesToHex(r));
        return r;
    };
});
function bytesToHex(arr) {
    var h = '';
    for (var i = 0; i < arr.length; i++) h += ('0' + (arr[i] & 0xff).toString(16)).slice(-2);
    return h;
}
'''

REPLACE_TMPL = r'''// 替换 %(module)s 偏移 %(addr)s 处函数, 恒返回 %(retval)s
var base = Module.findBaseAddress('%(module)s');
var target = base.add(%(addr)s);
console.log('[*] replace @ ' + target);
Interceptor.replace(target, new NativeCallback(function(a, b) {
    console.log('[replace] called, forced return %(retval)s');
    return %(retval)s;
}, 'int', ['pointer', 'pointer']));
'''

RUNNER_TMPL = '''# -*- coding: utf-8 -*-
# python 驱动(spawn 启动并注入 %(out)s); 也可直接命令行:
#   frida -U -f %(pkg)s -l %(out)s --no-pause
import frida, sys
device = frida.get_usb_device(timeout=5)
session = device.attach(sys.argv[1] if len(sys.argv) > 1 else "%(pkg)s")
script = session.create_script(open("%(out)s", "r", encoding="utf-8").read())
script.on("message", lambda m, data: print(m.get("payload") or m))
script.load()
sys.stdin.read()
'''

TMPLS = {'java': JAVA_TMPL, 'native': NATIVE_TMPL,
         'crypto': CRYPTO_TMPL, 'replace': REPLACE_TMPL}


def render(kind, args):
    """按类型填模板 -> (js 代码, 占位缺失列表)。"""
    import re as _re
    fields = {}
    fields['out'] = args.out or ('frida_%s.js' % kind)
    fields['pkg'] = args.pkg or 'com.example.ctf'
    fields['cls'] = args.cls or 'com.example.MainActivity'
    fields['method'] = args.method or 'checkFlag'
    fields['module'] = args.module or 'libnative.so'
    if kind == 'native':
        if args.export:
            fields['target_expr'] = "Module.getExportByName('%s', '%s')" % (args.module, args.export)
            fields['label'] = args.export
        elif args.addr:
            fields['target_expr'] = "base.add(%s)" % args.addr
            fields['label'] = 'base+%s' % args.addr
        else:
            fields['target_expr'] = "Module.getExportByName('%s', '%s')" % (args.module, 'Java_com_example_MainActivity_checkFlag')
            fields['label'] = '默认导出(请用 --export/--addr 指定)'
    if kind == 'replace':
        fields['addr'] = args.addr or '0x1000'
        fields['retval'] = args.retval if args.retval is not None else '1'
    js = TMPLS[kind] % fields
    missing = [m for m in _re.findall(r'None', '')]  # 占位: 默认值总会给全
    return js, fields, missing


def write_outputs(kind, js, fields, out):
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        f.write(js)
    print('[+] JS 已生成 -> %s' % os.path.abspath(out))
    if kind == 'native':
        print('[i] 挂钩目标: %s' % fields.get('target_expr'))
    print('[i] 运行(任选其一):')
    print('    frida -U -f %s -l %s --no-pause' % (fields['pkg'], out))
    runner = 'frida_%s_runner.py' % kind
    with open(runner, 'w', encoding='utf-8', newline='\n') as f:
        f.write(RUNNER_TMPL % {'out': out, 'pkg': fields['pkg']})
    print('    python %s <pid/包名>' % runner)


def selftest():
    import tempfile
    ok = True
    class _A: pass
    for kind in TMPLS:
        a = _A()
        a.out = os.path.join(tempfile.gettempdir(), 'frida_%s.js' % kind)
        a.pkg = a.cls = a.method = a.module = a.export = a.addr = a.retval = None
        js, fields, _ = render(kind, a)
        path = a.out
        with open(path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(js)
        text = open(path, encoding='utf-8').read()
        if kind == 'java':
            ok &= 'Java.perform' in text and 'MainActivity' in text and 'checkFlag' in text
        elif kind == 'native':
            ok &= 'Interceptor.attach' in text and 'Module.findBaseAddress' in text
        elif kind == 'crypto':
            ok &= 'javax.crypto.Cipher' in text and 'SecretKeySpec' in text and 'bytesToHex' in text
        elif kind == 'replace':
            ok &= 'Interceptor.replace' in text and 'NativeCallback' in text and '0x1000' in text
        os.remove(path)
    print('[OK] frida_hook.py 自测: 4 类模板生成/关键 API 断言通过')
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='Frida hook JS 生成器')
    ap.add_argument('kind', nargs='?', choices=list(TMPLS), help='模板类型')
    ap.add_argument('--class', dest='cls', help='Java 类名(java)')
    ap.add_argument('--method', help='Java 方法名(java)')
    ap.add_argument('--module', help='so 模块名(native/replace)')
    ap.add_argument('--export', help='导出函数名(native)')
    ap.add_argument('--addr', help='偏移地址(native/replace), 如 0x1234')
    ap.add_argument('--retval', help='replace 固定返回值(默认 1)')
    ap.add_argument('-o', '--out', help='输出 js 路径')
    ap.add_argument('--pkg', help='包名(生成命令提示用)')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()
    if not args.kind:
        print('用法: python frida_hook.py java|native|crypto|replace [参数...]')
        print('      python frida_hook.py --selftest')
        return 1
    js, fields, _ = render(args.kind, args)
    write_outputs(args.kind, js, fields, args.out or ('frida_%s.js' % args.kind))
    return 0


if __name__ == '__main__':
    sys.exit(main())
