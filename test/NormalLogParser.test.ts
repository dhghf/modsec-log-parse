/* eslint-disable no-undef */
import * as path from 'path'
import * as fs from "fs";
import { NormalLogParser } from "../src";

const examples = {
  file: path.resolve(`${__dirname}/log-examples/ebay_ssl_log`),
  line: '[08/Jun/2019:17:02:19 +0000] www.ebay.com 13.57.192.136 - - 64.126.41.245, 10.0.0.130 - "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" POST 200 "POST /rdr/f/v1/p1 HTTP/1.1"'
};

test('NormalLogParser.parseLine', () => {
  const normalLog = NormalLogParser.parseLine(examples.line);
  expect(normalLog.statusCode).toBe('200');
  expect(normalLog.date).toBe('08/Jun/2019:17:02:19 +0000');
  expect(normalLog.hostname).toBe('www.ebay.com');
  expect(normalLog.ip).toBe('64.126.41.245');
  expect(normalLog.method).toBe('POST');
  expect(normalLog.uri).toBe('/rdr/f/v1/p1');
  expect(normalLog.useragent).toBe('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36');
});

test('NormalLogParser.parseLog', () => {
  const data = fs.readFileSync(examples.file);
  const normalLogs = NormalLogParser.parseLog(data);
  expect(normalLogs.length).toBe(327);
});

