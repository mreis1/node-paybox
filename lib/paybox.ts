import * as path from 'path';
import * as fs from 'fs';
import * as crypto  from 'crypto';
import * as http from 'http';
import * as https from 'https';

var PAYBOX_SERVERS          = require('./servers.json');
var PAYBOX_RESPONSE_ERRORS  = require('./response-errors.json');


/**
 * Paybox Properties
 *
 * For further details check:
 * http://www1.paybox.com/espace-integrateur-documentation/dictionnaire-des-donnees/paybox-system/
 */
export interface IPayboxProps {
    ANNULE?	 //URL de retour en cas d’abandon	F
    ARCHIVAGE?	 //Référence archivage	F
    ATTENTE?	 //URL de retour en cas de paiement en attente de validation	F
    AUTOSEULE?	 //Ne pas envoyer ce paiement à la banque immédiatement	F
    CK_ONLY?	 //Forçage d’un mode de paiement Carte Cadeau uniquement (non mixte)	F
    CMD	 //Référence commande	O
    CODEFAMILLE	 //Données spécifique Cofinoga	C
    CURRENCYDISPLAY?	 //Configuration des devises affichées	F
    DATEn?	 //Paiement en plusieurs fois : Dates des échéances	F
    DEVISE	 //Devise (monnaie)	O
    DIFF?	 //Nombre de jours pour un paiement différé	F
    DISPLAY?	 //Timeout de la page de paiement	F
    EFFECTUE?	 //URL de retour en cas de succès	F
    EMPREINTE?	 //Empreinte fournie lors d’un premier paiement	F
    ENTITE?	 //Référence numérique d’un subdivision	F
    ERRORCODETEST?	 //Code erreur à renvoyer (pour tests)	F
    GROUPE	 //Groupe pour Paybox Version ++	C
    HASH	 //Algorithme utilisé pour la signature du message	O
    HMAC	 //Signature du message	O
    IDABT?	 //Numéro d’abonnement	F
    IDENTIFIANT	 //Identifiant client Paybox	O
    LANGUE?	 //Langue de la page de paiement	F
    MAXICHEQUE_DATA	 //Donnée spécifique Maxichèque	C
    NBCARTESKDO?	 //Nombre max de cartes cadeau utilisables par le porteur	F
    NETRESERVE_DATA	 //Données spécifique Net Reserve	C
    ONEY_DATA	 //Données spécifique Oney	C
    PAYPAL_DATA	 //Données spécifiques à Paypal	C
    PORTEUR	 //Adresse mail du client	O
    RANG	 //Numéro de rang fourni par la banque	O
    REFABONNE	 //Référence de l’abonne (version Plus)	C
    REFUSE?	 //URL de retour en cas de refus du paiement	F
    REPONDRE_A?	 //URL IPN	F
    RETOUR	 //Configuration de la réponse	O
    RUF1?	 //Méthode d’appel de l’URL IPN	F
    SITE	 //Numéro de site fourni par la banque	O
    SOURCE?	 //Format de la page de paiement (pour paiement mobile)	F
    TIME	 //Date et heure de la signature	O
    TOTAL	 //Montant	O
    TYPECARTE?	 //Forçage du moyen de paiement	F
    TYPEPAIEMENT?	 //Forçage du moyen de paiement	F


    // To allow PBX to be extended
    [key: string]: string;

    /*
        The following properties are not part of this interface because they start by a number.
        - 1EURO_CODEEXTERNE	    //Données spécifique 1euro.com	C
        - 1EURO_DATA	        //Données spécifique 1euro.com	C
        - 2MONTn	            //Paiement en plusieurs fois : Montant des échéances	F
        - 3DS	                //Désactivation 3-D Secure ponctuelle	F
    * */
}

/*Tableau 1 : Liste des variables Paybox System
Légende : O = Obligatoire ; F = Facultatif ; C = Conditionnel*/


export interface IPayboxTransactionCfg {
    /* The paybox URL */
    isTest: boolean;
    /* The block of servers that we wish to use.
     * Currently there's only a suite: 'system' */
    offer: ('system'),
    method: ('POST'|'GET'),
    key: string,
    PBX_: IPayboxProps
}


// http://www1.paybox.com/espace-integrateur-documentation/dictionnaire-des-donnees/paybox-system/

export class Paybox {
    /**
     * Checks identity of a response and if paybox returned an error
     * @param  {Object}   transaction   Transaction object returned by paybox.createTransaction()
     * @param  {Object}   datas         Datas received from Paybox
     * @param  {String}   pubkeyPath    The path where Paybox public key is stored on the server
     * @param  {Function} callback      Function to be called when checks are finished. Arguments are (error, transaction)
     * @return {void}
     */
    response(transaction, datas, pubkeyPath, callback){
        var _error = null;
        this.checkIdentity(transaction, datas, pubkeyPath, (identityOK) => {
            if(!identityOK){
                _error = 'This response is not from a paybox server';
            }
            else{
                _error = this.getResponseError(transaction, datas);
            }
            callback(_error, transaction);
        });
    }
    /**
     * Checks if there is an error in response datas
     * @param  {Object}   transaction   Transaction object returned by paybox.createTransaction()
     * @param  {Object}   datas         Datas received from Paybox
     * @return {String | NULL}          NULL if there is no error or a string explaining the error
     */
    getResponseError(transaction, datas){
        var _error = null;
        var _errorField = this.getErrorField(transaction);
        var _errorCode = datas[_errorField];
        if(_errorCode !== '00000'){
            Object.keys(PAYBOX_RESPONSE_ERRORS).map(function(error){
                var _regExp = new RegExp(error, 'g');
                if(_regExp.test(_errorCode)){
                    _error = PAYBOX_RESPONSE_ERRORS[error].replace(/%ERROR_CODE%/g, _errorCode);
                }
            });
            if(_error === null){
                _error = 'Unknown error returned by paybox : ' + _errorCode;
            }
        }
        return _error;
    }
    getKey(pathOrKey, callback){
        if(pathOrKey.charAt(0) === '/'){
            fs.readFile(pathOrKey, 'utf8', (err, key) => {
                callback(key);
            });
        }
        else{
            callback(pathOrKey);
        }
    }
    /**
     * Checks if a query is from Paybox
     * @param  {Object}   transaction   Transaction object returned by paybox.createTransaction()
     * @param  {Object}   datas         Datas received from Paybox
     * @param  {String}   pubkeyPath    The path where Paybox public key is stored on the server
     * @return {Boolean}
     */
    checkIdentity(transaction, datas, pubkeyPath, callback){
        this.getKey(pubkeyPath, (pubkey) => {
            /*console.log(pubkey);*/
            /*var pubkey     = fs.readFileSync(path.resolve(pubkeyPath), 'utf8');*/
            var _signField  = this.getSignField(transaction);
            var _check = true;
            if(_signField !== null){
                var _sign = datas[_signField];
                var _message = [];
                Object.keys(datas).map(function(field){
                    if(field !== _signField){
                        _message.push(field + '=' + encodeURIComponent(datas[field]));
                    }
                });
                let _messageStr = _message.join('&');
                _check = this.checkSignature(_messageStr, _sign, pubkey);
            }
            callback(_check);
        });
    }
    /**
     * Checks if a message and its signature match with the given public key
     * @param  {String} message   The message with format "field1=val1&field2=val2..."
     * @param  {String} signature The RSA SHA1 signature of the message
     * @param  {String} pubkey    The public key in UTF8
     * @return {Boolean}          If the message is signed by the owner of the public key
     */
    checkSignature(message, signature, pubkey){
        signature = new Buffer(decodeURIComponent(signature), 'base64');
        var check = crypto.createVerify('SHA1');
        check.update(message);
        return check.verify(pubkey, signature);
    }
    /**
     * Generates a signature and inserts it
     * @param  {Object} transaction The transaction returned by paybox.createTransaction()
     * @param  {String} key         Your private key in HEX format
     * @param  {String} hash        (optional) The hash algorithm to be used ('sha256'|'sha512') : Default = sha512
     * @return {Object}             The transaction signed
     */
    signTransaction(transaction, key, hash, callback){
        // fallback
        if (typeof hash === 'function'){
            callback = hash;
            hash = void 0;
        }
        var error = null;
        if (!transaction['PBX_'].TIME){
            transaction['PBX_'].TIME = (new Date()).toISOString();
        }
        if (!transaction['PBX_'].HASH){
            transaction['PBX_'].HASH = !hash ? 'SHA512' : hash.toUpperCase();
        }
        var _hmac = this.generateHMAC(transaction['PBX_'], key, hash);
        transaction['PBX_'].HMAC = _hmac;
        if(_hmac === null){
            error = 'Bad private key format, unable to generate signature';
        }
        callback(error, transaction);
    }
    /**
     * Generates all inputs of the form to submit to Paybox and inserts them in the transaction
     * @param  {Object} transaction The transaction returned by paybox.createTransaction()
     * @return {Object}             The transaction modified
     */
    generateFormBody(transaction){
        transaction.body = Object.keys(transaction['PBX_']).map(function(field){
            return '<input type="hidden" name="PBX_' + field + '" value="' + transaction['PBX_'][field] + '">';
        }).join('');
        return transaction;
    }
    /**
     * Generate an HMAC signature for given PBX fields
     * @param  {Object} PBXFields Paybox parameters without 'PBX_' prefix
     * @param  {String} key       The HEX format of the private key
     * @param  {String} hash      ('sha256'|'sha512')
     * @return {String}           Uppercase HEX format of the HMAC
     */
    generateHMAC(PBXFields, key, hash){
        var _hmac = null;
        try{
            var _message = Object.keys(PBXFields).map(function(field){
                return 'PBX_' + field + '=' + PBXFields[field];
            }).join('&');
            _hmac = this.generateSignature(_message, key, hash);
        }
        catch(e){}
        return _hmac;
    }
    generateSignature(message, key, hash){
        var _signature = null;
        try{
            var _key = new Buffer(key, 'hex');
            _signature = crypto.createHmac(hash || 'sha512', _key).update(message).digest('hex').toUpperCase();
        }
        catch(e){}
        return _signature;
    }
    /**
     * Finds the field name for the signature in the transaction
     * @param  {Ovject}         transaction   The transaction returned by paybox.createTransaction()
     * @return {String | null}                The field name or NULL if the signature was not asked in the transaction
     */
    getSignField(transaction){
        return this.getFieldName(transaction, 'K');
    }
    getErrorField(transaction){
        return this.getFieldName(transaction, 'E');
    }
    getFieldName(transaction, code){
        var _pbxRetour = transaction['PBX_'].RETOUR;
        var _fieldsRegExp = new RegExp('^.*;([^;]+):' + code.toUpperCase() + '[;]?.*', 'g');
        var _hasField = _fieldsRegExp.test(_pbxRetour);
        return _hasField ? _pbxRetour.replace(_fieldsRegExp, '$1') : null;
    }
    /**
     * Creates a transaction object with all needed informations to query paybox server
     * @param  {Object}   options  Options to create the transaction
     * @param  {Function} callback Function to be called when the transaction will be created. Arguments are (error, transaction)
     * @return {void}
     */
    createTransaction(options: IPayboxTransactionCfg, callback){
        this.getURL(options.offer, options.isTest === true, (err, url)=>{
            if(err !== null){
                return callback(err, null);
            }
            var _transaction = {
                'url'         : url,
                'expectedIP'  : '',
                'method'      : options.method || 'GET',
                'body'        : '',
                'hash'        : null,
                'PBX_'      : {
                    'RUF1'        : 'POST'
                }
            };

            Object.keys(options['PBX_']).map(function(field){
                _transaction['PBX_'][field.toUpperCase()] = options['PBX_'][field];
            });

            this.signTransaction(_transaction, options.key, _transaction.hash, (error, transaction) => {
                if(error === null){
                    transaction = this.generateFormBody(transaction);
                }
                callback(error, transaction);
            });
        });
    }
    /**
     * Extracts informations from an URL formated in a string
     * @param  {String} serverURL The URL with all informations like port, path, host, protocol (only http or https) (ex : https://domain.com:3021/my/path)
     * @return {Object}           An object with all informations extracted from the string
     */
    extractURLInfos(serverURL){
        var _infos = {
            isSSL : false,
            port  : 80,
            path  : '/load.html',
            host  : ''
        };
        _infos.host = serverURL
            .replace(/^(https?):\/\//g, function(p, protocol){
                _infos.isSSL  = protocol === 'https';
                _infos.port   = 443;
                return '';
            })
            .replace(/([^:|^\/]+)(.*)$/g, function(p, host, portAndPath){
                portAndPath
                    .replace(/^:(\d+)/g, function(p, port){
                        _infos.port = parseInt(port, 10);
                        return '';
                    })
                    .replace(/^:?(\/.*)/g, function(p, path){
                        _infos.path = path;
                        return '';
                    });
                return host;
            });
        return _infos;
    }
    /**
     * Recursive function to check all servers URL given
     * @param  {Array}    servers  List of URLs to check
     * @param  {Integer}  index    Current server index to check in servers Array
     * @param  {Function} callback Function to be called when checks are finished. 2 arguments : err, serverURL
     * @return {void}
     */
    checkNextServer(servers, index, callback){
        var _serverURL = servers[index];
        this.checkServer(_serverURL, (isAlive) => {
            if(isAlive){
                callback(null, _serverURL);
            }
            else if(++index < servers.length){
                this.checkNextServer(servers, index, callback);
            }
            else{
                callback('No alive server found');
            }
        });
    }
    /**
     * Makes a request to the given URL and check for a div#server_status and its content to be OK
     * @param  {String}   serverURL The URL with all needed parameters like port, path, host, protocol (only http or https)
     * @param  {Function} callback  Function to be called when the check is finished with 1 argument : Boolean isAlive
     * @return {void}
     */
    checkServer(serverURL, callback) {
        if(serverURL === undefined){
            return callback(false);
        }
        var _server     = this.extractURLInfos(serverURL);
        var reqLibrary  = _server.isSSL ? https : http;
        var req = (reqLibrary as any).request(_server);
        req.on('response', function(res){
            var _isAlive = false;
            res.setEncoding('utf8');
            res.on('data', function(body){
                body = body.replace(/< *br *\/? *>/g, '').replace(/\n| /g, '');
                _isAlive = (/id="server_status"/g).test(body) && (/>OK<\/div>/g).test(body);
            });
            res.on('end', function(){
                callback(_isAlive);
            });
        });
        req.on('error', function(err){
            callback(false);
        });
        req.end();
    }
    /**
     * Checks every server for given offer and return a valid one to the callback
     * @param  {String}             offer     The offer we want server URL
     * @param  {optional Boolean}   isTest    If it has to return a test URL
     * @param  {Function}           callback  Function to be called when checks are finished. 2 arguments : err, serverURL
     * @return {void}
     */
    getURL(offer, isTest, callback){
        if(callback === undefined){
            callback  = isTest;
            isTest    = false;
        }
        var _payboxSystemPath = '/cgi/MYchoix_pagepaiement.cgi';
        var servers = this.servers(offer, isTest);
        this.checkNextServer(servers, 0, function(err, serverURL){
            if(serverURL !== undefined){
                serverURL += _payboxSystemPath;
            }
            callback(err, serverURL);
        });
    }
    /**
     * Returns array of URLs for given offer
     * @param  {String}             offer   The offer the transaction is for. Eg "system"
     * @param  {optional Boolean}   test    If URLs needed are test servers. Default false.
     * @return {Array}                      List of servers URLs
     */
    servers(offer, test){
        var _serversURLs = [];
        if(PAYBOX_SERVERS[offer] !== undefined){
            _serversURLs = PAYBOX_SERVERS[offer][test ? 'test' : 'prod'];
        }
        return _serversURLs;
    }
};

export const paybox = new Paybox();
