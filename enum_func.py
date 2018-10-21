import frida
import sys

device = frida.get_usb_device()
session = device.attach("com.test.hello")

src = """
setImmediate(function() {
    function printStackTrace() {
        console.log("Open called from:\\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n") + "\\n");
    }
    function dumpMemory(addr, len, off) {
        var buf = Memory.readByteArray(addr, len);
        console.log(hexdump(buf, { offset: off, length: len, header: true, ansi: false }));
    }
    function printVar(addr, len) {
        var buf = Memory.readByteArray(addr, len);
        console.log(hexdump(buf, { offset: 0, length: len, header: true, ansi: false }));
    }

    function getTime() {
        return new Date().getTime();
    }
    function printCurTime(tag) {
        var d = new Date();
        send(tag + " : " + d.getHours() + ":" + d.getMinutes() + ":" + d.getSeconds() + ":" + d.getMilliseconds() + "\\t");
    }

    Module.enumerateExports("libcrypto.so", {
        onMatch: function (exp) {
            if (exp.type == "function") {
                send(exp.name);
            }
        },
        onComplete: function () {
            send('end');
        }
    });
});
"""
g_module_name = "libcrypto.so"

def on_message(message, data):
    if message['type'] == 'send':
        temp_str = message['payload']
        print(temp_str)
        if temp_str != 'end':
            f = open(g_module_name + "_func.txt", 'a', encoding='utf-8')
            func_str = "\nInterceptor.attach(Module.findExportByName('%s' , '%s'), {\n\tonEnter: function(args)\n\t{\n\t\tsend('------------------> enter %s\\\\n');\n\t},\n\tonLeave:function(retval)\n\t{\n\t\tsend('------------------> out %s\\\\n');\n\t}\n});" % (g_module_name, temp_str, temp_str, temp_str)# + "send('------------------> enter {func_name}\\n');\\n\\t}\\n\\ttonLeave:function(retval)\\n\\t{\\n\\t\\tsend('------------------> out {func_name}\\n');\\n\\t}});".format(module_name = g_module_name, func_name = temp_str)
            f.write(func_str)
            f.close()


script = session.create_script(src)
script.on("message", on_message)
script.load()
sys.stdin.read()