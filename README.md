## Express JS - Cross Site Request Forgery (CSRF)
### Easily add CSRF protection to your express js application

<br/>

[![NPM Version][npm-version-image]][npm-url]
[![NPM Downloads][npm-downloads-image]][npm-url]
[![Node.js Version][node-version-image]][node-version-url]
[![Build Status][travis-image]][travis-url]
[![Test Coverage][coveralls-image]][coveralls-url]

### Overview

This package is a simple yet effective middleware layer of CSRF protection to your express app. It creates a CSRF cookie for requests with methods `GET`, `HEAD`, `TRACE` and checks the CSRF cookie against a request header for `POST`, `PUT`, `PATCH`, `DELETE`. See these links for more details on this security implementation:
* https://docs.spring.io/spring-security/site/docs/5.0.x/reference/html/csrf.html
* https://angular.io/guide/security
* https://medium.com/@d.silvas/how-to-implement-csrf-protection-on-a-jwt-based-app-node-csurf-angular-bb90af2a9efd

### Installation

This is a [Node.js](https://nodejs.org/en/) module available through the
[npm registry](https://www.npmjs.com/). Installation is done using the
[`npm install` command](https://docs.npmjs.com/getting-started/installing-npm-packages-locally):

```sh
$ npm install express-csrf
```

### Demo

```js
const express = require('express');
const cookieParser = require('cookie-parser');
const expressCsrf = require('express-csrf');
 
const app = express();
app.use(cookieParser()); // cookie-parser is needed
app.use(expressCsrf.enable());
```

The middleware can also accept an `options` object, similar to the [csurf](https://www.npmjs.com/package/csurf) package:

```js
const express = require('express');
const cookieParser = require('cookie-parser');
const expressCsrf = require('express-csrf');
 
const app = express();
app.use(cookieParser()); // cookie-parser is needed
app.use(expressCsrf.enable({
  httpOnly: false,
  domain: 'some-domain',
  path: 'some-path'
}));
```