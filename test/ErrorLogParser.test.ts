/* eslint-disable no-undef */
import * as path from 'path';
import { ErrorLogParser } from "../src";

const example = {
  file: path.resolve(`${__dirname}/log-examples/ebay_ssl_error_log`),
  ruleLine: '[Sat Jun 08 17:18:02 2019] [-:error] 64.126.41.245, 10.0.0.130 [client 13.57.192.136] ModSecurity: Warning. Matched phrase "<!--" at ARGS:_rlogId. [file "/etc/httpd/modsecurity.d/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"] [line "311"] [id "941180"] [rev "2"] [msg "Node-Validator Blacklist Keywords"] [data "Matched Data: <!-- found within ARGS:_rlogId: <!-- rcmdid summary,rlogid t6n|ceb|qba?<kuvk~fgg~t`d*04131<7)pqtfwpu)osu)fgg~-fij-16b380a5c52-0x175 --><!-- siteid: 0, environment: production, appname: myebayweb, pageid: 2060353 -->"] [severity "CRITICAL"] [ver "OWASP_CRS/3.0.0"] [maturity "1"] [accuracy "8"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-xss"] [tag "OWASP_CRS/WEB_ATTACK/XSS"] [tag "WASCTC/WASC-8"] [tag "WASCTC/WASC-22"] [tag "OWASP_TOP_10/A3"] [tag "OWASP_AppSensor/IE1"] [tag "CAPEC-242"] [hostname "www.ebay.com"] [uri "/myb/jsErrorTrack"] [unique_id "XPvtyrkT6anO1lcrOtU0iQAAAAQ"], referer https://www.ebay.com/myb/Summary?MyEbay&gbh=1',
  proxyLine: '[Fri Jul 12 15:25:02 2019] [proxy:error] 82.132.216.33, 82.132.216.33 proxy AH01084: pass request body failed to 217.22.158.152:443 (www.example.com), referer https://www.example.com/',
  sslLine: '[Sat Jun 08 14:44:15 2019] [ssl:warn] ssl AH01909: www.ebay.com:443:0 server certificate does NOT include an ID which matches the server name'
};

test('ErrorLogParser.parseRuleError', () => {
  const ruleError = ErrorLogParser.parseRuleError(example.ruleLine);
  expect(ruleError.accuracy).toBe('8');

  expect(ruleError.data).toBe('Matched Data: <!-- found within ARGS:_rlogId: <!-- rcmdid summary,rlogid t6n|ceb|qba?<kuvk~fgg~t`d*04131<7)pqtfwpu)osu)fgg~-fij-16b380a5c52-0x175 --><!-- siteid: 0, environment: production, appname: myebayweb, pageid: 2060353 -->');
  expect(ruleError.date).toBe('Sat Jun 08 17:18:02 2019');
  expect(ruleError.file).toBe('/etc/httpd/modsecurity.d/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf');
  expect(ruleError.hostname).toBe('www.ebay.com');
  expect(ruleError.id).toBe('941180');
  expect(ruleError.ip).toBe('64.126.41.245');
  expect(ruleError.line).toBe('311');
  expect(ruleError.maturity).toBe('1');
  expect(ruleError.modsecurity).toBe(' Warning. Matched phrase "<!--" at ARGS:_rlogId. ');
  expect(ruleError.msg).toBe('Node-Validator Blacklist Keywords');
  expect(ruleError.rev).toBe('2');
  expect(ruleError.severity).toBe('CRITICAL');
  expect(ruleError.tags.length).toBeGreaterThan(0);
  expect(ruleError.type).toBe('rule');
  expect(ruleError.uri).toBe('/myb/jsErrorTrack');
  expect(ruleError.ver).toBe('OWASP_CRS/3.0.0');
});

test('ErrorLogParser.parseProxyError', () => {
  const proxyError = ErrorLogParser.parseProxyError(example.proxyLine);
  expect(proxyError.date).toBe('Fri Jul 12 15:25:02 2019');
  expect(proxyError.id).toBe('AH01084');
  expect(proxyError.msg).toBe('pass request body failed to 217.22.158.152:443 (www.example.com)');
  expect(proxyError.referer).toBe('https://www.example.com/');
  expect(proxyError.type).toBe('proxy');
});

test('ErrorLogParser.parseSSLError', () => {
  const sslError = ErrorLogParser.parseSSLError(example.sslLine);
  expect(sslError.type).toBe('ssl');
  expect(sslError.id).toBe('AH01909');
  expect(sslError.date).toBe('Sat Jun 08 14:44:15 2019');
  expect(sslError.msg).toBe('www.ebay.com:443:0 server certificate does NOT include an ID which matches the server name');
});

test('ErrorLogParser.parseLine', () => {
  const ruleError = ErrorLogParser.parseLine(example.ruleLine);
  const proxyError = ErrorLogParser.parseLine(example.proxyLine);
  const sslError = ErrorLogParser.parseLine(example.sslLine);
  if (ruleError && proxyError && sslError) {
    if (sslError.type == 'ssl') {
      expect(sslError.type).toBe('ssl');
      expect(sslError.id).toBe('AH01909');
      expect(sslError.date).toBe('Sat Jun 08 14:44:15 2019');
      expect(sslError.msg).toBe('www.ebay.com:443:0 server certificate does NOT include an ID which matches the server name');
    }
    if (proxyError.type == 'proxy') {
      expect(proxyError.date).toBe('Fri Jul 12 15:25:02 2019');
      expect(proxyError.id).toBe('AH01084');
      expect(proxyError.msg).toBe('pass request body failed to 217.22.158.152:443 (www.example.com)');
      expect(proxyError.referer).toBe('https://www.example.com/');
      expect(proxyError.type).toBe('proxy');
    }

    if (ruleError.type == 'rule') {
      expect(ruleError.accuracy).toBe('8');
      expect(ruleError.data).toBe('Matched Data: <!-- found within ARGS:_rlogId: <!-- rcmdid summary,rlogid t6n|ceb|qba?<kuvk~fgg~t`d*04131<7)pqtfwpu)osu)fgg~-fij-16b380a5c52-0x175 --><!-- siteid: 0, environment: production, appname: myebayweb, pageid: 2060353 -->');
      expect(ruleError.date).toBe('Sat Jun 08 17:18:02 2019');
      expect(ruleError.file).toBe('/etc/httpd/modsecurity.d/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf');
      expect(ruleError.hostname).toBe('www.ebay.com');
      expect(ruleError.id).toBe('941180');
      expect(ruleError.ip).toBe('64.126.41.245');
      expect(ruleError.line).toBe('311');
      expect(ruleError.maturity).toBe('1');
      expect(ruleError.modsecurity).toBe(' Warning. Matched phrase "<!--" at ARGS:_rlogId. ');
      expect(ruleError.msg).toBe('Node-Validator Blacklist Keywords');
      expect(ruleError.rev).toBe('2');
      expect(ruleError.severity).toBe('CRITICAL');
      expect(ruleError.tags.length).toBeGreaterThan(0);
      expect(ruleError.type).toBe('rule');
      expect(ruleError.uri).toBe('/myb/jsErrorTrack');
      expect(ruleError.ver).toBe('OWASP_CRS/3.0.0');
    }

  }
});

test('issue-#2', () => {
  const nonReferLine = '[Wed May 15 17:00:11 2019] [proxy:error] xx.xx.xx.xxx, xx.xx.xx.xxx proxy AH01084: pass request body failed to xxx.xx.xxx.xxx:xxx (www.example.com)';
  const proxyError = ErrorLogParser.parseProxyError(nonReferLine);
  expect(proxyError.date).toBe('Wed May 15 17:00:11 2019');
  expect(proxyError.id).toBe('AH01084');
  expect(proxyError.msg).toBe('pass request body failed to xxx.xx.xxx.xxx:xxx (www.example.com)');
  expect(proxyError.referer).toBe('');
  expect(proxyError.type).toBe('proxy');
  expect(proxyError).toBeDefined();
});
