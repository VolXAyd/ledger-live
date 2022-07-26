import Eth from "@ledgerhq/hw-app-eth";
import Transport from "@ledgerhq/hw-transport";
import { TypedDataUtils } from "eth-sig-util";
import { bufferToHex } from "ethereumjs-util";
import { getEnv } from "../../env";
import type { MessageData, Result } from "../../hw/signMessage/types";
import type { TypedMessageData, TypedMessage } from "./types";
type EthResolver = (
  arg0: Transport,
  arg1: MessageData | TypedMessageData
) => Promise<Result>;
export const domainHash = (message: TypedMessage) => {
  return TypedDataUtils.hashStruct(
    "EIP712Domain",
    message.domain,
    message.types,
    true
  );
};
export const messageHash = (message: TypedMessage) => {
  return TypedDataUtils.hashStruct(
    message.primaryType,
    message.message,
    message.types,
    true
  );
};

const resolver: EthResolver = async (
  transport,
  // @ts-expect-error only available on MessageData. (type guard)
  { path, message, rawMessage }
) => {
  const eth = new Eth(transport);
  const parsedMessage = (() => {
    try {
      return JSON.parse(message as string);
    } catch (e) {
      return message;
    }
  })();

  let result: Awaited<ReturnType<typeof eth.signPersonalMessage>>;
  if (typeof parsedMessage === "string") {
    result = await eth.signPersonalMessage(path, rawMessage.slice(2));
    result.v -= 27;
    // here the expected v is the parity/recoveryId, so we need to remove 27 (v is either 27 or 28)
  } else {
    result = getEnv("EXPERIMENTAL_EIP712")
      ? await eth.signEIP712Message(path, parsedMessage)
      : await eth.signEIP712HashedMessage(
          path,
          bufferToHex(domainHash(parsedMessage)),
          bufferToHex(messageHash(parsedMessage))
        );
    // result.v stays untouched for EIP712 as the expected v is already good (27 or 28)
  }

  let v = result.v.toString(16);
  if (v.length < 2) {
    v = "0" + v;
  }

  const signature = `0x${result["r"]}${result["s"]}${v}`;
  return {
    rsv: result,
    signature,
  };
};

export default resolver;
