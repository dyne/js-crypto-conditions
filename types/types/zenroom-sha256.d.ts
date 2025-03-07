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

  setScript(script: string): void;
  setData(data: Record<string, any>): void;
  setKeys(keys: Record<string, any>): void;

  getScript(): string;
  getData(): Record<string, any>;
  getKeys(): Record<string, any>;

  parseJson(json: ZenroomSha256Json): void;

  private getFingerprintContents(): Buffer;

  getAsn1JsonPayload(): ZenroomSha256Asn1Json;

  async sign(message: Buffer, condition_script: string, private_keys: Record<string, any>): Buffer;
  async validate(message: Buffer): boolean;
}

