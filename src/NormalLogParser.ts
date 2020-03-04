/**
 * This is a utility class which parses regular (non-error-related) ModSec logs.
 * @class NormalLogParser
 */
export class NormalLogParser {
  constructor() { }

  /**
   * This parses a single line
   * @param {string} line The line which represents a single line from a ModSec log
   * @returns {INormalLog}
   */
  public static parseLine(line: string): INormalLog {
    // Unlike a ModSec error log there really isn't a pattern to regular log-examples except for
    // spaces which aren't ideal for using so each property is specific about how it get's
    // it value
    const store: INormalLog = { // Object to be returned
      hostname: '',
      uri: '',
      method: '',
      statusCode: '',
      ip: '',
      useragent: line.substring(line.indexOf('"') + 1, line.indexOf('"', line.indexOf('"') + 1)),
      date: line.substring(1, line.indexOf(']'))
    };

    const uri = line.substring(line.indexOf('"', line.indexOf('"') + 1)).split(' ');
    const id = line.substring(line.indexOf(']') + 1, line.indexOf('"')).split(' ');
    store.method += uri[1];
    store.statusCode += uri[2];
    store.uri += uri[4];
    store.hostname += id[1];
    store.ip += id[5].replace(/(,)/, '');
    return store;
  }

  /**
   * This parses an entire file buffer
   * @param {Buffer} data The file buffer which represents a normal ModSec log.
   * @returns {INormalLog[]}
   */
  public static parseLog(data: Buffer): INormalLog[] {
    const logs: INormalLog[] = [];
    data.toString().split('\n').forEach((line: string) => {
      if (line.length > 5) {
        const store = NormalLogParser.parseLine(line);
        logs.push(store);
      }
    });
    return logs;
  }
}

export interface INormalLog {
  statusCode: string
  date: string
  hostname: string
  ip: string
  method: string
  uri: string
  useragent: string
}
