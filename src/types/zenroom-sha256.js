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

  parseJson (json) {
    console.log(json)
    this.setData(json.data)
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
      data: this.data,
      keys: this.keys
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
    if (!Buffer.isBuffer(message)) {
      throw new TypeError('Message must be a Buffer')
    }

    // Use native library if available (~60x faster)
    let result
    if (ed25519) {
      result = ed25519.Verify(message, this.signature, this.publicKey)
    } else {
      result = sign.detached.verify(bufferToUint8Array(message), bufferToUint8Array(this.signature), bufferToUint8Array(this.publicKey))
    }

    if (result !== true) {
      throw new ValidationError('Invalid ed25519 signature')
    }

    return true
  }
}

ZenroomSha256.TYPE_ID = 5
ZenroomSha256.TYPE_NAME = 'zenroom-sha-256'
ZenroomSha256.TYPE_ASN1_CONDITION = 'zenroomSha256Condition'
ZenroomSha256.TYPE_ASN1_FULFILLMENT = 'zenroomSha256Fulfillment'
ZenroomSha256.TYPE_CATEGORY = 'simple'

ZenroomSha256.CONSTANT_COST = 131072

export default ZenroomSha256;
