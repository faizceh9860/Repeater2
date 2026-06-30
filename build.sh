#!/bin/bash
# Usage: ./build.sh Repeater2.py jython-standalone-2.7.4.jar
# Self-contained — no extra files needed.

PY_FILE="$(realpath "${1:-Repeater2.py}")"
JYTHON_JAR="$(realpath "${2:-jython-standalone-2.7.4.jar}")"
OUT_JAR="$(pwd)/Repeater2.jar"
WORK="$(mktemp -d)"

echo "================================================"
echo "  Repeater2 JAR Builder"
echo "================================================"

# 1. Generate Burp API stubs
echo "[1/5] Generating Burp API stubs..."
mkdir -p "$WORK/stubs/burp"

cat > "$WORK/stubs/burp/IBurpExtender.java" << 'EOF'
package burp;
public interface IBurpExtender {
    void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks);
}
EOF

cat > "$WORK/stubs/burp/IBurpExtenderCallbacks.java" << 'EOF'
package burp;
import java.util.List;
public interface IBurpExtenderCallbacks {
    void setExtensionName(String name);
    void printOutput(String output);
    void printError(String error);
    IExtensionHelpers getHelpers();
    void registerHttpListener(IHttpListener listener);
    void registerContextMenuFactory(IContextMenuFactory factory);
    void addSuiteTab(ITab tab);
    byte[] makeHttpRequest(IHttpService service, byte[] request);
    List getProxyHistory();
    void registerMessageEditorTabFactory(IMessageEditorTabFactory factory);
    void saveExtensionSetting(String name, String value);
    String loadExtensionSetting(String name);
}
EOF

cat > "$WORK/stubs/burp/IExtensionHelpers.java" << 'EOF'
package burp;
public interface IExtensionHelpers {
    IRequestInfo analyzeRequest(IHttpRequestResponse request);
    IRequestInfo analyzeRequest(byte[] request);
    IResponseInfo analyzeResponse(byte[] response);
    byte[] buildHttpMessage(java.util.List headers, byte[] body);
    byte[] stringToBytes(String data);
    String bytesToString(byte[] data);
    IHttpService buildHttpService(String host, int port, boolean useHttps);
    IHttpService buildHttpService(String host, int port, String protocol);
    java.util.List analyzeParameters(byte[] request);
    String urlDecode(String data);
    String urlEncode(String data);
    byte[] base64Decode(String data);
    String base64Encode(byte[] data);
}
EOF

for iface in IHttpListener IContextMenuFactory ITab IMessageEditorTabFactory \
             IHttpRequestResponse IHttpService IRequestInfo IResponseInfo \
             IParameter ICookie IMessageEditor IMessageEditorTab \
             IMessageEditorController IContextMenuInvocation \
             IInterceptedProxyMessage IHttpRequestResponsePersisted IScanIssue; do
    echo "package burp; public interface $iface {}" > "$WORK/stubs/burp/$iface.java"
done

mkdir -p "$WORK/stubs_classes"
javac -d "$WORK/stubs_classes" $(find "$WORK/stubs" -name "*.java")
jar cf "$WORK/burp-stubs.jar" -C "$WORK/stubs_classes" .
echo "  Stubs OK"

# 2. Write + compile Java bootstrap (embedded inline)
echo "[2/5] Compiling Java bootstrap..."
mkdir -p "$WORK/src/burp"
cat > "$WORK/src/burp/BurpExtender.java" << 'EOF'
package burp;

import org.python.util.PythonInterpreter;
import org.python.core.*;
import java.io.InputStream;

public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        try {
            PySystemState state = new PySystemState();
            PythonInterpreter interp = new PythonInterpreter(null, state);
            InputStream is = getClass().getResourceAsStream("/Repeater2.py");
            if (is == null) {
                callbacks.printError("[Repeater2] Repeater2.py not found in JAR");
                return;
            }
            interp.execfile(is, "Repeater2.py");
            PyObject pyClass = interp.get("BurpExtender");
            if (pyClass != null) {
                PyObject instance = pyClass.__call__();
                instance.invoke("registerExtenderCallbacks", Py.java2py(callbacks));
            }
        } catch (Exception e) {
            callbacks.printError("[Repeater2] Load error: " + e.getMessage());
        }
    }
}
EOF

mkdir -p "$WORK/classes"
javac --release 11 \
    -cp "$JYTHON_JAR:$WORK/burp-stubs.jar" \
    -d "$WORK/classes" \
    "$WORK/src/burp/BurpExtender.java"
echo "  OK"

# 3. Extract Jython runtime
echo "[3/5] Extracting Jython runtime..."
mkdir -p "$WORK/merged"
cd "$WORK/merged"
jar xf "$JYTHON_JAR"
cd - >/dev/null

# 4. Overlay Java class + embed Python script
echo "[4/5] Embedding extension..."
cp -r "$WORK/classes/"* "$WORK/merged/"
cp "$PY_FILE" "$WORK/merged/Repeater2.py"

# 5. Repackage
echo "[5/5] Packaging JAR..."
cd "$WORK/merged"
jar cf "$OUT_JAR" .
cd - >/dev/null

rm -rf "$WORK"

echo "================================================"
echo "  [+] Done: Repeater2.jar"
echo ""
echo "  Load in Burp Suite:"
echo "  Extender -> Extensions -> Add"
echo "  Extension Type: Java"
echo "  Select: Repeater2.jar"
echo "================================================"
