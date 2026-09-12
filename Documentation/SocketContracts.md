# Socket contracts

## fg_SendVectored

Send spans in order and return aggregate progress, possibly ending inside a span.

## fg_Receive

Zero progress can mean would-block or EOF; o_bEndOfStream distinguishes them. TLS requires EOF to detect
missing close notification.
