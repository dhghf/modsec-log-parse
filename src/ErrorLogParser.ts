export interface IModSecError {
    id: string;
    type: string;
    date: string;
    msg: string;
}

export interface IProxyError extends IModSecError {
    referer: string;
    type: 'proxy'
    id: string;
    date: string;
    msg: string;
}

export interface IRuleError extends IModSecError {
    accuracy: string;
    data: string;
    file: string;
    hostname: string;
    ip: string;
    line: string;
    maturity: string;
    modsecurity: string;
    rev: string;
    severity: string;
    tags: string[];
    uri: string;
    ver: string;
    type: 'rule';
    id: string;
    date: string;
    msg: string;
}

export interface ISSLError extends IModSecError {
    type: 'ssl';
    id: string;
    date: string;
    msg: string;
}

/**
 * This is a utility class which helps parse a ModSec error log or line. To utilize this class
 * use methods parseLog to parse an entire file buffer or parseLine to parse a single line. If
 * you already know what type of error it is then use the corresponding methods.
 * @class ErrorLogParser
 */
export class ErrorLogParser {
    constructor() { }

    /**
     * This parses an entire file buffer that represents a ModSec error log.
     * @param {Buffer} buffer
     * @returns {IModSecError[]}
     */
    public static parseLog(buffer: Buffer): IModSecError[] {
        const modSecErrors: IModSecError[] = [];
        // Split the buffer at each new-line this will allow us to parse each line individually
        buffer.toString().split('\n').forEach((errorLine: string) => {
            // If the line is populated then continue to parse it
            if (errorLine.length > 0) {
                const modSecError = ErrorLogParser.parseLine(errorLine);
                // If this line was parsed properly then add it to the array.
                if (modSecError)
                    modSecErrors.push(modSecError);
            }
        });
        // Finally return the successfully parsed lines.
        return modSecErrors
    }

    /**
     * This method parses a "ssl" error. This error occurs relating to SSL issues.
     * @param {string} line
     * @returns {ISSLError}
     */
    public static parseSSLError(line: string): ISSLError {
        const split = line.split(': ');
        const spaces = split[0].split(' ');
        return {
            type: 'ssl',
            msg: split[1],
            id: spaces[spaces.length - 1],
            date: line.substr(1, line.indexOf(']') - 1)
        };
    }

    /**
     * This method parses a "proxy" error. This error occurs when an error occurs relating to
     * proxies.
     * @param {string} line
     * @returns {IProxyError}
     */
    public static parseProxyError(line: string): IProxyError {
        const split: string[] = line.split(': ');
        const spaces = split[0].split(' ');
        const referer = split[1].match(/referer(.*)/g);
        const msg = split[1].match(/^[^,]*/g);

        return {
            type: 'proxy',
            id: spaces[spaces.length - 1],
            date: line.substr(1, line.indexOf(']') - 1),
            msg: msg ? msg[0] : '',
            referer: referer ? referer[0].replace(/(referer )/g, '') : ''
        };
    }

    /**
     * This method parses a "rule" error. This error occurs when a rule has been broken.
     * @param {string} line A line from a ModSec error log
     * @returns {IRuleError}
     */
    public static parseRuleError(line: string): IRuleError {
        let ruleError: IRuleError = {
            accuracy: "",
            data: "",
            file: "",
            hostname: "",
            id: "",
            line: "",
            maturity: "",
            msg: "",
            rev: "",
            severity: "",
            tags: [],
            uri: "",
            ver: "",
            date: '',
            ip: '',
            modsecurity: '',
            type: 'rule'
        };
        const entrees = line.split('[');
        entrees.forEach((entree: string) => {
            switch (entrees.indexOf(entree)) {
                case 1:
                    ruleError.date = entree.split(']')[0];
                    break;
                case 2:
                    ruleError.ip = entree.split(' ')[1].replace(/[,]/, '');
                    break;
                case 3:
                    ruleError.modsecurity = entree.replace(/(..*..ModSecurity:)/g, '');
                    break;
                default:
                    if (entree.includes('"')) {
                        const key: string = entree.split('"')[0].trim();
                        const value: string = entree.split('"')[1].trim();
                        if (Object.keys(ruleError).includes(key)) {
                            switch (key) {
                                case 'accuracy':
                                    ruleError.accuracy = value;
                                    break;
                                case 'data':
                                    ruleError.data = value;
                                    break;
                                case 'file':
                                    ruleError.file = value;
                                    break;
                                case 'hostname':
                                    ruleError.hostname = value;
                                    break;
                                case 'id':
                                    ruleError.id = value;
                                    break;
                                case 'line':
                                    ruleError.line = value;
                                    break;
                                case 'maturity':
                                    ruleError.maturity = value;
                                    break;
                                case 'msg':
                                    ruleError.msg = value;
                                    break;
                                case 'rev':
                                    ruleError.rev = value;
                                    break;
                                case 'severity':
                                    ruleError.severity = value;
                                    break;
                                case 'uri':
                                    ruleError.uri = value;
                                    break;
                                case 'ver':
                                    ruleError.ver = value;
                                    break;
                                case 'date':
                                    ruleError.date = value;
                                    break;
                                case 'ip':
                                    ruleError.ip = value;
                                    break;
                                case 'modsecurity':
                                    ruleError.modsecurity = value;
                                    break;
                            }
                        }
                    }
                    if (entree.startsWith('tag "')) {
                        ruleError.tags.push(entree.split('"')[1])
                    }
                    break
            }
        });

        return ruleError;
    }

    /**
     * This parses a single line
     * @param {string} line A line from a ModSec error log to parse from
     * @returns {IRuleError | ISSLError | IProxyError | undefined}
     */
    public static parseLine(line: string): IRuleError | ISSLError | IProxyError | undefined {
        const split = line.split('[');
        const type = split[2].split(':')[0];
        switch (type) {
            case '-':
                return ErrorLogParser.parseRuleError(line);
            case 'ssl':
                return ErrorLogParser.parseSSLError(line);
            case 'proxy':
            case 'proxy_http':
                return ErrorLogParser.parseProxyError(line);
        }
    }
}
