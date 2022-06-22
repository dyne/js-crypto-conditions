import type {
  ZenroomSha256Asn1Json,
  ZenroomSha256Json,
  TypeAsn1Condition,
  TypeAsn1Fulfillment,
  TypeCategory,
  TypeId,
  TypeName,
} from '.';
import type BaseSha256 from './base-sha256';

export const TYPE_ID: TypeId.ZenroomSha256;
export const TYPE_NAME: TypeName.ZenroomSha256;
export const TYPE_ASN1_CONDITION: TypeAsn1Condition.ZenroomSha256;
export const TYPE_ASN1_FULFILLMENT: TypeAsn1Fulfillment.ZenroomSha256;
export const TYPE_CATEGORY: TypeCategory.ZenroomSha256;

export const CONSTANT_COST = 131072;
export default class ZenroomSha256 extends BaseSha256 {
  private publicKey: Record<string, any>;
  private signature: Record<string, any>;

  static TYPE_ID: TypeId.ZenroomSha256;
  static TYPE_NAME: TypeName.ZenroomSha256;
  static TYPE_ASN1_CONDITION: TypeAsn1Condition.ZenroomSha256;
  static TYPE_ASN1_FULFILLMENT: TypeAsn1Fulfillment.ZenroomSha256;
  static TYPE_CATEGORY: TypeCategory.ZenroomSha256;

  static CONSTANT_COST: number;

  constructor();

  parseJson(json: ZenroomSha256Json): void;

  private getFingerprintContents(): Buffer;

  getAsn1JsonPayload(): ZenroomSha256Asn1Json;

  validate(message: Buffer): boolean;
}

