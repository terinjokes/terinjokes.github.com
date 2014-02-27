---
layout: post
title: Replacing packages in a Browserify bundle
categories:
- blog
---
As a developer on a large Backbone application built with [Browserify](https://github.com/substack/node-browserify), there are a number of occasions where I want to replace one dependency with another. In this specific case, I wanted to swap `underscore` for `lodash`.

Browserify already supports this with the "browser field" in `package.json`.

> There is a special "browser" field you can set in your package.json on a per-module basis to override file resolution for browser-specific versions of files.

This only works for resolution within your package, if any of your dependency packages require Underscore they'll get Underscore. It is suboptimal to us to ship both Lo-Dash and Underscore, as is maintaining a fork simply to replace the dependency.

The Browserify transform [browserify-swap](https://github.com/thlorenz/browserify-swap) allows you swap dependencies in certain packages, as defined via the `@packages` key, while generating the output bundle.

As I want to replace Underscore in Backbone, Marionnette and related packages, the configuration seemed pretty straight-forward.

```json
/* package.json */
{
  "browserify": {
    "transform": [
      "browserify-swap"
    ]
  },
  "browserify-swap": {
    "@packages": [
      "backbone",
      "marionette",
      "backbone.babysitter",
      "backbone.wreqr"
    ],
    "all": {
      "underscore.js$": "lodash"
    }
  }
}
```

I was a bit discouraged that Underscore was still present in the output bundle. After triple-checking that my configuration was valid, I broke out the node debugger to find what was wrong.

I believed `browserify-swap` to swap packages while resolving the require calls. The transform actually checks if the current file [matches a RegEx](https://github.com/thlorenz/browserify-swap/blob/fbb9ca86c8af14e3fa21a75852f6251ea86f45d7/index.js#L38) defined in the `package.json` file and replaces the contents to require the swapped in package.

With this information in hand, it became clear that we needed to swap for the `underscore` package.

```json
/* package.json */
{
  "browserify": {
    "transform": [
      "browserify-swap"
    ]
  },
  "browserify-swap": {
    "@packages": [
      "underscore"
    ],
    "all": {
      "underscore.js$": "lodash"
    }
  }
}
```

This swap would happen for each instance of Underscore in the bundle, but only the one instance of Lo-Dash would be included.