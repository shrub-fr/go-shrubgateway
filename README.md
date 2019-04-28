# go-shrubgateway

Shrub https subscheme implementation https://shrub.fr/

The command shrubgateway starts a web server listening for TLS connections on the local host's loopback interface on port 58273, using the local CA at "<user's home directory>/.shrubgateway".

This server implements the protocol associated to the Shrub https subscheme, as defined in draft-shrub.fr-shrub at https://shrub.fr/doc/spec/shrub/
