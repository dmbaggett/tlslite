# /bin/sh
PYTHONPATH=$INKY/deps/thirdparty-tlslite python ../scripts/tls.py server -k serverX509Key.pem -c serverX509Cert.pem -t TACK1.pem localhost:4443

