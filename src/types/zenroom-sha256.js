/**
 * @module types
 */

import { sign } from 'tweetnacl'
import BaseSha256 from './base-sha256'
import MissingDataError from '../errors/missing-data-error'
import ValidationError from '../errors/validation-error'
import bufferToUint8Array from '../util/buffer-to-uint-array'
import { ZenroomFingerprintContents as Asn1ZenroomFingerprintContents } from '../schemas/fingerprint'
import { zencode_exec } from 'zenroom'
import {default as stringify} from 'json-stable-stringify';

/**
 * Zenroom: Zenroom condition.
 *
 * This condition implements execution of arbitrary zencode scripts
 *
 * (For zenroom?)
 * ED25519 is assigned the type ID 4. It relies only on the ED25519 feature
 * suite which corresponds to a bitmask of 0x20.
 */
class ZenroomSha256 extends BaseSha256 {
  constructor () {
    super()
    this.script = null
    this.data = null
    this.keys = null
  }

  setScript (script) {
    if (typeof script != "string") {
      throw new Error('The script must be a string')
    }

    this.script = script
  }

  setData (data) {

    this.data = data
  }

  setKeys (keys) {
    this.keys = keys
  }

  getScript () {
    return this.script
  }

  getData () {
    return this.data
  }

  getKeys () {
    return this.keys
  }

  parseJson (json) {
    this.setScript(json.script.toString('utf-8'))
    this.setData(JSON.parse(json.data.toString('utf-8')))
    this.setKeys(JSON.parse(json.keys.toString('utf-8')))
  }

  /**
   * Produce the contents of the condition hash.
   *
   * This function is called internally by the `getCondition` method.
   *
   * @return {Buffer} Encoded contents of fingerprint hash.
   *
   * @private
   */
  getFingerprintContents () {
    if (!this.script) {
      throw new MissingDataError('Requires a zencode script')
    }

    return Asn1ZenroomFingerprintContents.encode({
      script: this.script
    })
  }

  getAsn1JsonPayload () {
    return {
      script: this.script,
      data: JSON.stringify(this.data),
      keys: JSON.stringify(this.keys)
    }
  }

  /**
   * Calculate the cost of fulfilling this condition.
   *
   * The cost of the Ed25519 condition is 2^17 = 131072.
   *
   * @return {Number} Expected maximum cost to fulfill this condition
   * @private
   */
  calculateCost () {
    return ZenroomSha256.CONSTANT_COST
  }

  /**
   * Verify the signature of this Ed25519 fulfillment.
   *
   * The signature of this Ed25519 fulfillment is verified against the provided
   * message and public key.
   *
   * @param {Buffer} message Message to validate against.
   * @return {Boolean} Whether this fulfillment is valid.
   */
  validate (message) {
      throw new Error('Not implemented yet')
  }


  async sign(messageStr, condition_script, keyring) {
    let message = JSON.parse(messageStr.toString('utf-8'))
    const data = this.data || {}
    try {
      data.asset = message.asset.data
    } catch(e) {}
    const result = await zencode_exec(condition_script,
      { keys: JSON.stringify({keyring}),
        data: JSON.stringify(data) })

    message['metadata'] = message['metadata'] || {}

    Object.assign(message['metadata'], {data: JSON.parse(result.result),
                                        logs: result.logs})
    return Buffer.from(JSON.stringify(message))

  }

  async validate(messageStr) {
    const message = JSON.parse(messageStr.toString('utf-8'))
    let data = this.data || {}
    try {
      data.asset = message.asset.data
    } catch(e) {}
    try {
      data.result = message.metadata.data
    } catch(e) {}

    const zen = await zencode_exec(this.script,
                                   {keys: JSON.stringify(this.keys),
                                   data: JSON.stringify(data)})

    const result = JSON.parse(zen.result)
    return message.metadata.result &&
      stringify(message.metadata.result) == stringify(result)
  }
}

ZenroomSha256.TYPE_ID = 5
ZenroomSha256.TYPE_NAME = 'zenroom-sha-256'
ZenroomSha256.TYPE_ASN1_CONDITION = 'zenroomSha256Condition'
ZenroomSha256.TYPE_ASN1_FULFILLMENT = 'zenroomSha256Fulfillment'
ZenroomSha256.TYPE_CATEGORY = 'simple'

ZenroomSha256.CONSTANT_COST = 131072

export default ZenroomSha256;
