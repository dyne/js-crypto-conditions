/* eslint-disable strict, no-console, object-shorthand */

'use strict'

const path = require('path')
const { merge } = require('webpack-merge')

const development = require('./webpack.development.js')
const production = require('./webpack.production.js')

const AddVendorsPlugin = require('./plugins/add-vendors-plugin')

const paths = {
  entry: path.resolve(__dirname, 'src/index.js'),
  bundle: path.resolve(__dirname, 'dist/browser')
}

const outputs = (base, env, mapping, overrides) => {
  const collection = []
  const library = 'CryptoConditions'
  // const windowLibrary = 'CryptoConditions'

  const environment = env === 'production' ? production : development
  const ext = env === 'production' ? 'min.js' : 'js'

  Object.entries(mapping).forEach(([target, extension]) => {
    const filename = `[name].${library}.${extension}.${ext}`

    const compiled = {
      output: {
        filename: filename,
        // setting library mess up with export
        // library: target === 'window' ? windowLibrary : library,
        libraryTarget: target,
        path: paths.bundle
      },
      plugins: [new AddVendorsPlugin(`${library}.${extension}.${ext}`)]
    }

    collection.push(merge(base, environment, compiled, overrides))
  })

  return collection
}

module.exports = {
  outputs,
  paths
}
