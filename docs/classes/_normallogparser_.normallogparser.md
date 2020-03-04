[modsec-log-parse](../README.md) › [Globals](../globals.md) › ["NormalLogParser"](../modules/_normallogparser_.md) › [NormalLogParser](_normallogparser_.normallogparser.md)

# Class: NormalLogParser

This is a utility class which parses regular (non-error-related) ModSec logs.

## Hierarchy

* **NormalLogParser**

## Index

### Constructors

* [constructor](_normallogparser_.normallogparser.md#constructor)

### Methods

* [parseLine](_normallogparser_.normallogparser.md#static-parseline)
* [parseLog](_normallogparser_.normallogparser.md#static-parselog)

## Constructors

###  constructor

\+ **new NormalLogParser**(): *[NormalLogParser](_normallogparser_.normallogparser.md)*

*Defined in [NormalLogParser.ts:5](https://github.com/dhghf/modsec-log-parse/blob/1605c65/src/NormalLogParser.ts#L5)*

**Returns:** *[NormalLogParser](_normallogparser_.normallogparser.md)*

## Methods

### `Static` parseLine

▸ **parseLine**(`line`: string): *[INormalLog](../interfaces/_normallogparser_.inormallog.md)*

*Defined in [NormalLogParser.ts:13](https://github.com/dhghf/modsec-log-parse/blob/1605c65/src/NormalLogParser.ts#L13)*

This parses a single line

**Parameters:**

Name | Type | Description |
------ | ------ | ------ |
`line` | string | The line which represents a single line from a ModSec log |

**Returns:** *[INormalLog](../interfaces/_normallogparser_.inormallog.md)*

___

### `Static` parseLog

▸ **parseLog**(`data`: Buffer): *[INormalLog](../interfaces/_normallogparser_.inormallog.md)[]*

*Defined in [NormalLogParser.ts:42](https://github.com/dhghf/modsec-log-parse/blob/1605c65/src/NormalLogParser.ts#L42)*

This parses an entire file buffer

**Parameters:**

Name | Type | Description |
------ | ------ | ------ |
`data` | Buffer | The file buffer which represents a normal ModSec log. |

**Returns:** *[INormalLog](../interfaces/_normallogparser_.inormallog.md)[]*
