[modsec-log-parse](../README.md) › [Globals](../globals.md) › ["ErrorLogParser"](../modules/_errorlogparser_.md) › [ErrorLogParser](_errorlogparser_.errorlogparser.md)

# Class: ErrorLogParser

This is a utility class which helps parse a ModSec error log or line. To utilize this class
use methods parseLog to parse an entire file buffer or parseLine to parse a single line. If
you already know what type of error it is then use the corresponding methods.

## Hierarchy

* **ErrorLogParser**

## Index

### Constructors

* [constructor](_errorlogparser_.errorlogparser.md#constructor)

### Methods

* [parseLine](_errorlogparser_.errorlogparser.md#static-parseline)
* [parseLog](_errorlogparser_.errorlogparser.md#static-parselog)
* [parseProxyError](_errorlogparser_.errorlogparser.md#static-parseproxyerror)
* [parseRuleError](_errorlogparser_.errorlogparser.md#static-parseruleerror)
* [parseSSLError](_errorlogparser_.errorlogparser.md#static-parsesslerror)

## Constructors

###  constructor

\+ **new ErrorLogParser**(): *[ErrorLogParser](_errorlogparser_.errorlogparser.md)*

*Defined in [ErrorLogParser.ts:49](https://github.com/dhghf/modsec-log-parse/blob/1605c65/src/ErrorLogParser.ts#L49)*

**Returns:** *[ErrorLogParser](_errorlogparser_.errorlogparser.md)*

## Methods

### `Static` parseLine

▸ **parseLine**(`line`: string): *[IRuleError](../interfaces/_errorlogparser_.iruleerror.md) | [ISSLError](../interfaces/_errorlogparser_.isslerror.md) | [IProxyError](../interfaces/_errorlogparser_.iproxyerror.md) | undefined*

*Defined in [ErrorLogParser.ts:216](https://github.com/dhghf/modsec-log-parse/blob/1605c65/src/ErrorLogParser.ts#L216)*

This parses a single line

**Parameters:**

Name | Type | Description |
------ | ------ | ------ |
`line` | string | A line from a ModSec error log to parse from |

**Returns:** *[IRuleError](../interfaces/_errorlogparser_.iruleerror.md) | [ISSLError](../interfaces/_errorlogparser_.isslerror.md) | [IProxyError](../interfaces/_errorlogparser_.iproxyerror.md) | undefined*

___

### `Static` parseLog

▸ **parseLog**(`buffer`: Buffer): *[IModSecError](../interfaces/_errorlogparser_.imodsecerror.md)[]*

*Defined in [ErrorLogParser.ts:57](https://github.com/dhghf/modsec-log-parse/blob/1605c65/src/ErrorLogParser.ts#L57)*

This parses an entire file buffer that represents a ModSec error log.

**Parameters:**

Name | Type |
------ | ------ |
`buffer` | Buffer |

**Returns:** *[IModSecError](../interfaces/_errorlogparser_.imodsecerror.md)[]*

___

### `Static` parseProxyError

▸ **parseProxyError**(`line`: string): *[IProxyError](../interfaces/_errorlogparser_.iproxyerror.md)*

*Defined in [ErrorLogParser.ts:95](https://github.com/dhghf/modsec-log-parse/blob/1605c65/src/ErrorLogParser.ts#L95)*

This method parses a "proxy" error. This error occurs when an error occurs relating to
proxies.

**Parameters:**

Name | Type |
------ | ------ |
`line` | string |

**Returns:** *[IProxyError](../interfaces/_errorlogparser_.iproxyerror.md)*

___

### `Static` parseRuleError

▸ **parseRuleError**(`line`: string): *[IRuleError](../interfaces/_errorlogparser_.iruleerror.md)*

*Defined in [ErrorLogParser.ts:115](https://github.com/dhghf/modsec-log-parse/blob/1605c65/src/ErrorLogParser.ts#L115)*

This method parses a "rule" error. This error occurs when a rule has been broken.

**Parameters:**

Name | Type | Description |
------ | ------ | ------ |
`line` | string | A line from a ModSec error log |

**Returns:** *[IRuleError](../interfaces/_errorlogparser_.iruleerror.md)*

___

### `Static` parseSSLError

▸ **parseSSLError**(`line`: string): *[ISSLError](../interfaces/_errorlogparser_.isslerror.md)*

*Defined in [ErrorLogParser.ts:78](https://github.com/dhghf/modsec-log-parse/blob/1605c65/src/ErrorLogParser.ts#L78)*

This method parses a "ssl" error. This error occurs relating to SSL issues.

**Parameters:**

Name | Type |
------ | ------ |
`line` | string |

**Returns:** *[ISSLError](../interfaces/_errorlogparser_.isslerror.md)*
