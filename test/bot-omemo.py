# from https://github.com/Syndace/slixmpp-omemo/blob/main/examples/echo_client.py

from argparse import ArgumentParser
from getpass import getpass
import json
import logging
import sys
from typing import Any, Dict, FrozenSet, Literal, Optional, Union

from omemo.storage import Just, Maybe, Nothing, Storage
from omemo.types import DeviceInformation, JSONType

from slixmpp.clientxmpp import ClientXMPP
from slixmpp.jid import JID
from slixmpp.plugins import register_plugin  # type: ignore[attr-defined]
from slixmpp.stanza import Message
from slixmpp.xmlstream.handler import CoroutineCallback
from slixmpp.xmlstream.matcher import MatchXPath

from slixmpp_omemo import TrustLevel, XEP_0384

import traceback
import random


log = logging.getLogger(__name__)


class StorageImpl(Storage):
    """
    Example storage implementation that stores all data in a single JSON file.
    """

    JSON_FILE = "/tmp/storage.json"

    def __init__(self) -> None:
        super().__init__()

        self.__data: Dict[str, JSONType] = {}
        try:
            with open(self.JSON_FILE, encoding="utf8") as f:
                self.__data = json.load(f)
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    async def _load(self, key: str) -> Maybe[JSONType]:
        if key in self.__data:
            return Just(self.__data[key])

        return Nothing()

    async def _store(self, key: str, value: JSONType) -> None:
        self.__data[key] = value
        with open(self.JSON_FILE, "w", encoding="utf8") as f:
            json.dump(self.__data, f)

    async def _delete(self, key: str) -> None:
        self.__data.pop(key, None)
        with open(self.JSON_FILE, "w", encoding="utf8") as f:
            json.dump(self.__data, f)


class XEP_0384Impl(XEP_0384):  # pylint: disable=invalid-name
    """
    Example implementation of the OMEMO plugin for Slixmpp.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # pylint: disable=redefined-outer-name
        super().__init__(*args, **kwargs)

        # Just the type definition here
        self.__storage: Storage

    def plugin_init(self) -> None:
        self.__storage = StorageImpl()

        super().plugin_init()

    @property
    def storage(self) -> Storage:
        return self.__storage

    @property
    def _btbv_enabled(self) -> bool:
        return True

    async def _devices_blindly_trusted(
        self,
        blindly_trusted: FrozenSet[DeviceInformation],
        identifier: Optional[str]
    ) -> None:
        log.info(f"[{identifier}] Devices trusted blindly: {blindly_trusted}")

    async def _prompt_manual_trust(
        self,
        manually_trusted: FrozenSet[DeviceInformation],
        identifier: Optional[str]
    ) -> None:
        # Since BTBV is enabled and we don't do any manual trust adjustments in the example, this method
        # should never be called. All devices should be automatically trusted blindly by BTBV.

        # To show how a full implementation could look like, the following code will prompt for a trust
        # decision using `input`:
        session_mananger = await self.get_session_manager()

        for device in manually_trusted:
            while True:
                answer = input(f"[{identifier}] Trust the following device? (yes/no) {device}")
                if answer in { "yes", "no" }:
                    await session_mananger.set_trust(
                        device.bare_jid,
                        device.identity_key,
                        TrustLevel.TRUSTED.value if answer == "yes" else TrustLevel.DISTRUSTED.value
                    )
                    break
                print("Please answer yes or no.")


register_plugin(XEP_0384Impl)


class OmemoEchoClient(ClientXMPP):
    """
    A simple Slixmpp bot that will echo encrypted messages it receives, along with a short thank you message.

    For details on how to build a client with Slixmpp, look at examples in the Slixmpp repository.
    """

    def __init__(self, jid: str, password: str) -> None:
        super().__init__(jid, password)

        self.add_event_handler("session_start", self.start)
        self.register_handler(CoroutineCallback(
            "Messages",
            MatchXPath(f"{{{self.default_ns}}}message"),
            self.message_handler  # type: ignore[arg-type]
        ))


    def start(self, _event: Any) -> None:
        """
        Process the session_start event.

        Typical actions for the session_start event are requesting the roster and broadcasting an initial
        presence stanza.

        Args:
            event: An empty dictionary. The session_start event does not provide any additional data.
        """

        self.send_presence()
        self.get_roster()  # type: ignore[no-untyped-call]

    async def message_handler(self, stanza: Message) -> None:
        """
        Process incoming message stanzas. Be aware that this also includes MUC messages and error messages. It
        is usually a good idea to check the messages's type before processing or sending replies.

        Args:
            msg: The received message stanza. See the documentation for stanza objects and the Message stanza
                to see how it may be used.
        """

        xep_0384: XEP_0384 = self["xep_0384"]

        mto = stanza["from"]

        mtype = stanza["type"]
        if mtype not in { "chat", "normal" }:
            return

        namespace = xep_0384.is_encrypted(stanza)
        if namespace is None:
            self.plain_reply(
                mto,
                mtype,
                f"Unencrypted message or unsupported message encryption: {stanza['body']}"
            )
            return

        log.debug(f"Message in namespace {namespace} received: {stanza}")

        try:
            message, device_information = await xep_0384.decrypt_message(stanza)
            log.debug(f"Information about sender: {device_information}")
        except Exception as e:  # pylint: disable=broad-exception-caught
            print("Exception", traceback.format_exc())
            self.plain_reply(mto, mtype, f"Error {type(e).__name__}: {e}")
            return

        for i in range(0, random.randint(0, 3)):
            try:
                await self.encrypted_reply(mto, mtype, message)
            except Exception as e:  # pylint: disable=broad-exception-caught
                print("Exception", traceback.format_exc())
                self.plain_reply(mto, mtype, f"Error {type(e).__name__}: {e}")

    def plain_reply(self, mto: JID, mtype: Literal["chat", "normal"], reply: str) -> None:
        """
        Helper to reply with plain messages.

        Args:
            mto: The recipient JID.
            mtype: The message type.
            reply: The text content of the reply.
        """

        stanza = self.make_message(mto=mto, mtype=mtype)
        stanza["body"] = reply
        stanza.send()

    async def encrypted_reply(
        self,
        mto: JID,
        mtype: Literal["chat", "normal"],
        reply: Union[Message, str]
    ) -> None:
        """
        Helper to reply with encrypted messages.

        Args:
            mto: The recipient JID.
            mtype: The message type.
            reply: Either the message stanza to encrypt and reply with, or the text content of the reply.
        """

        xep_0384: XEP_0384 = self["xep_0384"]

        if isinstance(reply, str):
            msg = reply
            reply = self.make_message(mto=mto, mtype=mtype)
            reply["body"] = msg

        reply.set_to(mto)
        reply.set_from(self.boundjid)

        # It might be a good idea to strip everything bot the body from the stanza, since some things might
        # break when echoed.
        messages, encryption_errors = await xep_0384.encrypt_message(reply, mto)

        if len(encryption_errors) > 0:
            log.info(f"There were non-critical errors during encryption: {encryption_errors}")

        for namespace, message in messages.items():
            message["eme"]["namespace"] = namespace
            message["eme"]["name"] = self["xep_0380"].mechanisms[namespace]
            message.send()


if __name__ == "__main__":
    xmpp = OmemoEchoClient("user@localhost", "userpass")
    xmpp.register_plugin("xep_0380")  # Explicit Message Encryption
    xmpp.register_plugin("xep_0384", module=sys.modules[__name__])  # OMEMO
    xmpp.connect(disable_starttls=True)
    xmpp.process()  # type: ignore[no-untyped-call]
