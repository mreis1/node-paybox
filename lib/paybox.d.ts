/**
 * Paybox Properties
 *
 * For further details check:
 * http://www1.paybox.com/espace-integrateur-documentation/dictionnaire-des-donnees/paybox-system/
 */
export interface IPayboxProps {
    ANNULE?: any;
    ARCHIVAGE?: any;
    ATTENTE?: any;
    AUTOSEULE?: any;
    CK_ONLY?: any;
    CMD: any;
    CODEFAMILLE: any;
    CURRENCYDISPLAY?: any;
    DATEn?: any;
    DEVISE: any;
    DIFF?: any;
    DISPLAY?: any;
    EFFECTUE?: any;
    EMPREINTE?: any;
    ENTITE?: any;
    ERRORCODETEST?: any;
    GROUPE: any;
    HASH: any;
    HMAC: any;
    IDABT?: any;
    IDENTIFIANT: any;
    LANGUE?: any;
    MAXICHEQUE_DATA: any;
    NBCARTESKDO?: any;
    NETRESERVE_DATA: any;
    ONEY_DATA: any;
    PAYPAL_DATA: any;
    PORTEUR: any;
    RANG: any;
    REFABONNE: any;
    REFUSE?: any;
    REPONDRE_A?: any;
    RETOUR: any;
    RUF1?: any;
    SITE: any;
    SOURCE?: any;
    TIME: any;
    TOTAL: any;
    TYPECARTE?: any;
    TYPEPAIEMENT?: any;
    [key: string]: string;
}
export interface IPayboxTransactionCfg {
    isTest: boolean;
    offer: ('system');
    method: ('POST' | 'GET');
    key: string;
    PBX_: IPayboxProps;
}
export declare class Paybox {
    /**
     * Checks identity of a response and if paybox returned an error
     * @param  {Object}   transaction   Transaction object returned by paybox.createTransaction()
     * @param  {Object}   datas         Datas received from Paybox
     * @param  {String}   pubkeyPath    The path where Paybox public key is stored on the server
     * @param  {Function} callback      Function to be called when checks are finished. Arguments are (error, transaction)
     * @return {void}
     */
    response(transaction: any, datas: any, pubkeyPath: any, callback: any): void;
    /**
     * Checks if there is an error in response datas
     * @param  {Object}   transaction   Transaction object returned by paybox.createTransaction()
     * @param  {Object}   datas         Datas received from Paybox
     * @return {String | NULL}          NULL if there is no error or a string explaining the error
     */
    getResponseError(transaction: any, datas: any): any;
    getKey(pathOrKey: any, callback: any): void;
    /**
     * Checks if a query is from Paybox
     * @param  {Object}   transaction   Transaction object returned by paybox.createTransaction()
     * @param  {Object}   datas         Datas received from Paybox
     * @param  {String}   pubkeyPath    The path where Paybox public key is stored on the server
     * @return {Boolean}
     */
    checkIdentity(transaction: any, datas: any, pubkeyPath: any, callback: any): void;
    /**
     * Checks if a message and its signature match with the given public key
     * @param  {String} message   The message with format "field1=val1&field2=val2..."
     * @param  {String} signature The RSA SHA1 signature of the message
     * @param  {String} pubkey    The public key in UTF8
     * @return {Boolean}          If the message is signed by the owner of the public key
     */
    checkSignature(message: any, signature: any, pubkey: any): boolean;
    /**
     * Generates a signature and inserts it
     * @param  {Object} transaction The transaction returned by paybox.createTransaction()
     * @param  {String} key         Your private key in HEX format
     * @param  {String} hash        (optional) The hash algorithm to be used ('sha256'|'sha512') : Default = sha512
     * @return {Object}             The transaction signed
     */
    signTransaction(transaction: any, key: any, hash: any, callback: any): void;
    /**
     * Generates all inputs of the form to submit to Paybox and inserts them in the transaction
     * @param  {Object} transaction The transaction returned by paybox.createTransaction()
     * @return {Object}             The transaction modified
     */
    generateFormBody(transaction: any): any;
    /**
     * Generate an HMAC signature for given PBX fields
     * @param  {Object} PBXFields Paybox parameters without 'PBX_' prefix
     * @param  {String} key       The HEX format of the private key
     * @param  {String} hash      ('sha256'|'sha512')
     * @return {String}           Uppercase HEX format of the HMAC
     */
    generateHMAC(PBXFields: any, key: any, hash: any): any;
    generateSignature(message: any, key: any, hash: any): any;
    /**
     * Finds the field name for the signature in the transaction
     * @param  {Ovject}         transaction   The transaction returned by paybox.createTransaction()
     * @return {String | null}                The field name or NULL if the signature was not asked in the transaction
     */
    getSignField(transaction: any): any;
    getErrorField(transaction: any): any;
    getFieldName(transaction: any, code: any): any;
    /**
     * Creates a transaction object with all needed informations to query paybox server
     * @param  {Object}   options  Options to create the transaction
     * @param  {Function} callback Function to be called when the transaction will be created. Arguments are (error, transaction)
     * @return {void}
     */
    createTransaction(options: IPayboxTransactionCfg, callback: any): void;
    /**
     * Extracts informations from an URL formated in a string
     * @param  {String} serverURL The URL with all informations like port, path, host, protocol (only http or https) (ex : https://domain.com:3021/my/path)
     * @return {Object}           An object with all informations extracted from the string
     */
    extractURLInfos(serverURL: any): {
        isSSL: boolean;
        port: number;
        path: string;
        host: string;
    };
    /**
     * Recursive function to check all servers URL given
     * @param  {Array}    servers  List of URLs to check
     * @param  {Integer}  index    Current server index to check in servers Array
     * @param  {Function} callback Function to be called when checks are finished. 2 arguments : err, serverURL
     * @return {void}
     */
    checkNextServer(servers: any, index: any, callback: any): void;
    /**
     * Makes a request to the given URL and check for a div#server_status and its content to be OK
     * @param  {String}   serverURL The URL with all needed parameters like port, path, host, protocol (only http or https)
     * @param  {Function} callback  Function to be called when the check is finished with 1 argument : Boolean isAlive
     * @return {void}
     */
    checkServer(serverURL: any, callback: any): any;
    /**
     * Checks every server for given offer and return a valid one to the callback
     * @param  {String}             offer     The offer we want server URL
     * @param  {optional Boolean}   isTest    If it has to return a test URL
     * @param  {Function}           callback  Function to be called when checks are finished. 2 arguments : err, serverURL
     * @return {void}
     */
    getURL(offer: any, isTest: any, callback: any): void;
    /**
     * Returns array of URLs for given offer
     * @param  {String}             offer   The offer the transaction is for. Eg "system"
     * @param  {optional Boolean}   test    If URLs needed are test servers. Default false.
     * @return {Array}                      List of servers URLs
     */
    servers(offer: any, test: any): any[];
}
export declare const paybox: Paybox;
