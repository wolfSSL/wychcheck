#!/usr/bin/env python3
"""
Generate testvectors_rfc/ JSON files from RFC normative test vectors.

Run from the project root or from tools/:
    python3 tools/make_rfc_vectors.py

All values are transcribed directly from the referenced RFC sections.
No network access required.

Sources
-------
  RFC 3394 §4       AES Key Wrap (2002)
  RFC 5869 App A    HKDF-SHA-256 (2010)
  RFC 7748 §6.1-2   X25519, X448 (2016)
  RFC 8032 §7.1,7.4 EdDSA: Ed25519, Ed448 (2017)
  RFC 8439 §2.8.2   ChaCha20-Poly1305 AEAD (2018)
"""

import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR = os.path.join(PROJECT_DIR, "testvectors_rfc")


def write_json(filename, data):
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    n = sum(len(g["tests"]) for g in data["testGroups"])
    print(f"  {filename} ({n} test{'s' if n != 1 else ''})")


# ---------------------------------------------------------------------------
# RFC 8439 §2.8.2  ChaCha20-Poly1305 AEAD
# ---------------------------------------------------------------------------

def make_rfc8439():
    return {
        "algorithm": "CHACHA20-POLY1305",
        "schema": "aead_test_schema_v1.json",
        "numberOfTests": 1,
        "header": ["RFC 8439 Section 2.8.2 ChaCha20-Poly1305 AEAD test vector"],
        "notes": {},
        "testGroups": [
            {
                "ivSize": 96,
                "keySize": 256,
                "tagSize": 128,
                "type": "AeadTest",
                "source": {"name": "rfc8439", "version": "2018"},
                "tests": [
                    {
                        "tcId": 1,
                        "comment": "RFC 8439 Section 2.8.2",
                        "flags": [],
                        "key":  "808182838485868788898a8b8c8d8e8f"
                                "909192939495969798999a9b9c9d9e9f",
                        "iv":   "070000004041424344454647",
                        "aad":  "50515253c0c1c2c3c4c5c6c7",
                        "msg":  "4c616469657320616e642047656e746c"
                                "656d656e206f662074686520636c6173"
                                "73206f66202739393a20496620492063"
                                "6f756c64206f6666657220796f75206f"
                                "6e6c79206f6e652074697020666f7220"
                                "746865206675747572652c2073756e73"
                                "637265656e20776f756c642062652069"
                                "742e",
                        "ct":   "d31a8d34648e60db7b86afbc53ef7ec2"
                                "a4aded51296e08fea9e2b5a736ee62d6"
                                "3dbea45e8ca9671282fafb69da92728b"
                                "1a71de0a9e060b2905d6a5b67ecd3b36"
                                "92ddbd7f2d778b8c9803aee328091b58"
                                "fab324e4fad675945585808b4831d7bc"
                                "3ff4def08e4b7a9de576d26586cec64b"
                                "6116",
                        "tag":  "1ae10b594f09e26a7e902ecbd0600691",
                        "result": "valid",
                    }
                ],
            }
        ],
    }


# ---------------------------------------------------------------------------
# RFC 3394 §4  AES Key Wrap
# ---------------------------------------------------------------------------

def make_rfc3394():
    return {
        "algorithm": "AES-WRAP",
        "schema": "keywrap_test_schema_v1.json",
        "numberOfTests": 6,
        "header": ["RFC 3394 Section 4 AES Key Wrap test vectors"],
        "notes": {},
        "testGroups": [
            {
                "keySize": 128,
                "type": "KeywrapTest",
                "source": {"name": "rfc3394", "version": "2002"},
                "tests": [
                    {
                        "tcId": 1,
                        "comment": "RFC 3394 4.1 Wrap 128 bits with 128-bit key",
                        "flags": [],
                        "key": "000102030405060708090a0b0c0d0e0f",
                        "msg": "00112233445566778899aabbccddeeff",
                        "ct":  "1fa68b0a8112b447aef34bd8fb5a7b82"
                               "9d3e862371d2cfe5",
                        "result": "valid",
                    },
                ],
            },
            {
                "keySize": 192,
                "type": "KeywrapTest",
                "source": {"name": "rfc3394", "version": "2002"},
                "tests": [
                    {
                        "tcId": 2,
                        "comment": "RFC 3394 4.2 Wrap 128 bits with 192-bit key",
                        "flags": [],
                        "key": "000102030405060708090a0b0c0d0e0f"
                               "1011121314151617",
                        "msg": "00112233445566778899aabbccddeeff",
                        "ct":  "96778b25ae6ca435f92b5b97c050aed2"
                               "468ab8a17ad84e5d",
                        "result": "valid",
                    },
                    {
                        "tcId": 4,
                        "comment": "RFC 3394 4.4 Wrap 192 bits with 192-bit key",
                        "flags": [],
                        "key": "000102030405060708090a0b0c0d0e0f"
                               "1011121314151617",
                        "msg": "00112233445566778899aabbccddeeff"
                               "0001020304050607",
                        "ct":  "031d33264e15d33268f24ec260743edc"
                               "e1c6c7ddee725a936ba814915c6762d2",
                        "result": "valid",
                    },
                ],
            },
            {
                "keySize": 256,
                "type": "KeywrapTest",
                "source": {"name": "rfc3394", "version": "2002"},
                "tests": [
                    {
                        "tcId": 3,
                        "comment": "RFC 3394 4.3 Wrap 128 bits with 256-bit key",
                        "flags": [],
                        "key": "000102030405060708090a0b0c0d0e0f"
                               "101112131415161718191a1b1c1d1e1f",
                        "msg": "00112233445566778899aabbccddeeff",
                        "ct":  "64e8c3f9ce0f5ba263e9777905818a2a"
                               "93c8191e7d6e8ae7",
                        "result": "valid",
                    },
                    {
                        "tcId": 5,
                        "comment": "RFC 3394 4.5 Wrap 192 bits with 256-bit key",
                        "flags": [],
                        "key": "000102030405060708090a0b0c0d0e0f"
                               "101112131415161718191a1b1c1d1e1f",
                        "msg": "00112233445566778899aabbccddeeff"
                               "0001020304050607",
                        "ct":  "a8f9bc1612c68b3ff6e6f4fbe30e71e4"
                               "769c8b80a32cb8958cd5d17d6b254da1",
                        "result": "valid",
                    },
                    {
                        "tcId": 6,
                        "comment": "RFC 3394 4.6 Wrap 256 bits with 256-bit key",
                        "flags": [],
                        "key": "000102030405060708090a0b0c0d0e0f"
                               "101112131415161718191a1b1c1d1e1f",
                        "msg": "00112233445566778899aabbccddeeff"
                               "000102030405060708090a0b0c0d0e0f",
                        "ct":  "28c9f404c4b810f4cbccb35cfb87f826"
                               "3f5786e2d80ed326cbc7f0e71a99f43b"
                               "fb988b9b7a02dd21",
                        "result": "valid",
                    },
                ],
            },
        ],
    }


# ---------------------------------------------------------------------------
# RFC 7748 §6.1  X25519
# ---------------------------------------------------------------------------

def make_rfc7748_x25519():
    return {
        "algorithm": "XDH",
        "schema": "xdh_comp_schema_v1.json",
        "numberOfTests": 1,
        "header": ["RFC 7748 Section 6.1 X25519 test vector"],
        "notes": {},
        "testGroups": [
            {
                "type": "XdhComp",
                "source": {"name": "rfc7748", "version": "2016"},
                "curve": "curve25519",
                "tests": [
                    {
                        "tcId": 1,
                        "comment": "RFC 7748 Section 6.1",
                        "flags": [],
                        "public":  "de9edb7d7b7dc1b4d35b61c2ece43537"
                                   "3f8343c85b78674dadfc7e146f882b4f",
                        "private": "77076d0a7318a57d3c16c17251b26645"
                                   "df4c2f87ebc0992ab177fba51db92c2a",
                        "shared":  "4a5d9d5ba4ce2de1728e3bf480350f25"
                                   "e07e21c947d19e3376f09b3c1e161742",
                        "result": "valid",
                    }
                ],
            }
        ],
    }


# ---------------------------------------------------------------------------
# RFC 7748 §6.2  X448
# ---------------------------------------------------------------------------

def make_rfc7748_x448():
    return {
        "algorithm": "XDH",
        "schema": "xdh_comp_schema_v1.json",
        "numberOfTests": 1,
        "header": ["RFC 7748 Section 6.2 X448 test vector"],
        "notes": {},
        "testGroups": [
            {
                "type": "XdhComp",
                "source": {"name": "rfc7748", "version": "2016"},
                "curve": "curve448",
                "tests": [
                    {
                        "tcId": 1,
                        "comment": "RFC 7748 Section 6.2",
                        "flags": [],
                        "public":  "3eb7a829b0cd20f5bcfc0b599b6feccf"
                                   "6da4627107bdb0d4f345b43027d8b972"
                                   "fc3e34fb4232a13ca706dcb57aec3dae"
                                   "07bdc1c67bf33609",
                        "private": "9a8f4925d1519f5775cf46b04b5800d4"
                                   "ee9ee8bae8bc5565d498c28dd9c9baf5"
                                   "74a9419744897391006382a6f127ab1d"
                                   "9ac2d8c0a598726b",
                        "shared":  "07fff4181ac6cc95ec1c16a94a0f74d1"
                                   "2da232ce40a77552281d282bb60c0b56"
                                   "fd2464c335543936521c24403085d59a"
                                   "449a5037514a879d",
                        "result": "valid",
                    }
                ],
            }
        ],
    }


# ---------------------------------------------------------------------------
# RFC 5869 Appendix A  HKDF-SHA-256
# Groups are by IKM size so A.1 and A.3 (22-byte IKM) share a group.
# ---------------------------------------------------------------------------

def make_rfc5869():
    return {
        "algorithm": "HKDF-SHA-256",
        "schema": "hkdf_test_schema_v1.json",
        "numberOfTests": 3,
        "header": ["RFC 5869 Appendix A HKDF-SHA-256 test vectors"],
        "notes": {},
        "testGroups": [
            {
                "type": "HkdfTest",
                "source": {"name": "rfc5869", "version": "2010"},
                "keySize": 176,  # 22-byte IKM (A.1 and A.3 share this size)
                "tests": [
                    {
                        "tcId": 1,
                        "comment": "RFC 5869 A.1",
                        "flags": [],
                        "ikm":  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
                                "0b0b0b0b0b0b",
                        "salt": "000102030405060708090a0b0c",
                        "info": "f0f1f2f3f4f5f6f7f8f9",
                        "size": 42,
                        "okm":  "3cb25f25faacd57a90434f64d0362f2a"
                                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                                "34007208d5b887185865",
                        "result": "valid",
                    },
                    {
                        "tcId": 3,
                        "comment": "RFC 5869 A.3 (no salt, no info)",
                        "flags": [],
                        "ikm":  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
                                "0b0b0b0b0b0b",
                        "salt": "",
                        "info": "",
                        "size": 42,
                        "okm":  "8da4e775a563c18f715f802a063c5a31"
                                "b8a11f5c5ee1879ec3454e5f3c738d2d"
                                "9d201395faa4b61a96c8",
                        "result": "valid",
                    },
                ],
            },
            {
                "type": "HkdfTest",
                "source": {"name": "rfc5869", "version": "2010"},
                "keySize": 640,  # 80-byte IKM (A.2)
                "tests": [
                    {
                        "tcId": 2,
                        "comment": "RFC 5869 A.2",
                        "flags": [],
                        "ikm":  "000102030405060708090a0b0c0d0e0f"
                                "101112131415161718191a1b1c1d1e1f"
                                "202122232425262728292a2b2c2d2e2f"
                                "303132333435363738393a3b3c3d3e3f"
                                "404142434445464748494a4b4c4d4e4f",
                        "salt": "606162636465666768696a6b6c6d6e6f"
                                "707172737475767778797a7b7c7d7e7f"
                                "808182838485868788898a8b8c8d8e8f"
                                "909192939495969798999a9b9c9d9e9f"
                                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                        "info": "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0"
                                "e1e2e3e4e5e6e7e8e9eaebecedeeef"
                                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                        "size": 82,
                        "okm":  "b11e398dc80327a1c8e7f78c596a4934"
                                "4f012eda2d4efad8a050cc4c19afa97c"
                                "59045a99cac7827271cb41c65e590e09"
                                "da3275600c2f09b8367793a9aca3db71"
                                "cc30c58179ec3e87c14c01d5c1f3434f"
                                "1d87",
                        "result": "valid",
                    },
                ],
            },
        ],
    }


# ---------------------------------------------------------------------------
# RFC 8032 §7.1 (Ed25519) and §7.4 (Ed448)
#
# tcId=7 and tcId=8 share a public key (same key, different context):
#   tcId=7  Ed448pure, no context    → valid
#   tcId=8  Ed448ctx, context="foo"  → acceptable
#           wolfssl wc_ed448_verify_msg() calls with NULL/0 context and
#           cannot verify Ed448ctx signatures, so "acceptable" is correct.
# ---------------------------------------------------------------------------

def make_rfc8032():  # noqa: C901 (long but mechanical)
    def ed25519_group(pk, tcid, comment, msg, sig, result="valid"):
        return {
            "type": "EddsaVerify",
            "source": {"name": "rfc8032", "version": "2017"},
            "publicKey": {
                "type": "EDDSAPublicKey",
                "curve": "edwards25519",
                "keySize": 255,
                "pk": pk,
            },
            "tests": [{"tcId": tcid, "comment": comment,
                        "flags": [], "msg": msg, "sig": sig,
                        "result": result}],
        }

    def ed448_group(pk, tests):
        return {
            "type": "EddsaVerify",
            "source": {"name": "rfc8032", "version": "2017"},
            "publicKey": {
                "type": "EDDSAPublicKey",
                "curve": "edwards448",
                "keySize": 448,
                "pk": pk,
            },
            "tests": tests,
        }

    def tc448(tcid, comment, msg, sig, result="valid"):
        return {"tcId": tcid, "comment": comment,
                "flags": [], "msg": msg, "sig": sig, "result": result}

    groups = [
        # --- Ed25519 §7.1 ---
        ed25519_group(
            pk="d75a980182b10ab7d54bfed3c964073a"
               "0ee172f3daa62325af021a68f707511a",
            tcid=1, comment="RFC 8032 7.1 TEST 1", msg="",
            sig="e5564300c360ac729086e2cc806e828a"
                "84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46b"
                "d25bf5f0595bbe24655141438e7a100b",
        ),
        ed25519_group(
            pk="3d4017c3e843895a92b70aa74d1b7ebc"
               "9c982ccf2ec4968cc0cd55f12af4660c",
            tcid=2, comment="RFC 8032 7.1 TEST 2", msg="72",
            sig="92a009a9f0d4cab8720e820b5f642540"
                "a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c"
                "387b2eaeb4302aeeb00d291612bb0c00",
        ),
        ed25519_group(
            pk="fc51cd8e6218a1a38da47ed00230f058"
               "0816ed13ba3303ac5deb911548908025",
            tcid=3, comment="RFC 8032 7.1 TEST 3", msg="af82",
            sig="6291d657deec24024827e69c3abe01a3"
                "0ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc659"
                "4a7c15e9716ed28dc027beceea1ec40a",
        ),
        ed25519_group(
            pk="278117fc144c72340f67d0f2316e8386"
               "ceffbf2b2428c9c51fef7c597f1d426e",
            tcid=4, comment="RFC 8032 7.1 TEST 1024",
            msg=(
                "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
                "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
                "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
                "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
                "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
                "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
                "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
                "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
                "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed"
                "185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb"
                "2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc2"
                "4554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27"
                "088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbc"
                "c2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0"
                "707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128b"
                "ab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51"
                "addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429"
                "ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb"
                "751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8"
                "c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff"
                "8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34d"
                "ff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e0"
                "8d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
                "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
                "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
                "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6"
                "aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb"
                "93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50"
                "d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef13"
                "69546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db"
                "2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0"
                "618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
            ),
            sig="0aab4c900501b3e24d7cdf4663326a3a"
                "87df5e4843b2cbdb67cbf6e460fec350"
                "aa5371b1508f9f4528ecea23c436d94b"
                "5e8fcd4f681e30a6ac00a9704a188a03",
        ),
        ed25519_group(
            pk="ec172b93ad5e563bf4932c70e1245034"
               "c35467ef2efd4d64ebf819683467e2bf",
            tcid=5, comment="RFC 8032 7.1 TEST SHA(abc)",
            # message is SHA-512("abc") = 64 bytes
            msg="ddaf35a193617abacc417349ae204131"
                "12e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd"
                "454d4423643ce80e2a9ac94fa54ca49f",
            sig="dc2a4459e7369633a52b1bf277839a00"
                "201009a3efbf3ecb69bea2186c26b589"
                "09351fc9ac90b3ecfdfbc7c66431e030"
                "3dca179c138ac17ad9bef1177331a704",
        ),

        # --- Ed448 §7.4 ---
        ed448_group(
            pk="5fd7449b59b461fd2ce787ec616ad46a"
               "1da1342485a70e1f8a0ea75d80e96778"
               "edf124769b46c7061bd6783df1e50f6c"
               "d1fa1abeafe8256180",
            tests=[
                tc448(6, "RFC 8032 7.4 Blank", msg="",
                      sig="533a37f6bbe457251f023c0d88f976ae"
                          "2dfb504a843e34d2074fd823d41a591f"
                          "2b233f034f628281f2fd7a22ddd47d78"
                          "28c59bd0a21bfd3980ff0d2028d4b18a"
                          "9df63e006c5d1c2d345b925d8dc00b41"
                          "04852db99ac5c7cdda8530a113a0f4db"
                          "b61149f05a7363268c71d95808ff2e65"
                          "2600"),
            ],
        ),
        ed448_group(
            # tcId=7 (Ed448pure, valid) and tcId=8 (Ed448ctx, acceptable)
            # share the same public key — same key-pair, different signing modes.
            pk="43ba28f430cdff456ae531545f7ecd0a"
               "c834a55d9358c0372bfa0c6c6798c086"
               "6aea01eb00742802b8438ea4cb82169c"
               "235160627b4c3a9480",
            tests=[
                tc448(7, "RFC 8032 7.4 1 octet", msg="03",
                      sig="26b8f91727bd62897af15e41eb43c377"
                          "efb9c610d48f2335cb0bd0087810f435"
                          "2541b143c4b981b7e18f62de8ccdf633"
                          "fc1bf037ab7cd779805e0dbcc0aae1cb"
                          "cee1afb2e027df36bc04dcecbf154336"
                          "c19f0af7e0a6472905e799f1953d2a0f"
                          "f3348ab21aa4adafd1d234441cf807c0"
                          "3a00"),
                tc448(8,
                      "RFC 8032 7.4 1 octet with context foo"
                      " (Ed448ctx; wolfssl wc_ed448_verify_msg uses no context)",
                      msg="03",
                      sig="d4f8f6131770dd46f40867d6fd5d5055"
                          "de43541f8c5e35abbcd001b32a89f7d2"
                          "151f7647f11d8ca2ae279fb842d60721"
                          "7fce6e042f6815ea000c85741de5c8da"
                          "1144a6a1aba7f96de42505d7a7298524"
                          "fda538fccbbb754f578c1cad10d54d0d"
                          "5428407e85dcbc98a49155c13764e66c"
                          "3c00",
                      result="acceptable"),
            ],
        ),
        ed448_group(
            pk="dcea9e78f35a1bf3499a831b10b86c90"
               "aac01cd84b67a0109b55a36e9328b1e3"
               "65fce161d71ce7131a543ea4cb5f7e9f"
               "1d8b00696447001400",
            tests=[tc448(9, "RFC 8032 7.4 11 octets",
                         msg="0c3e544074ec63b0265e0c",
                         sig="1f0a8888ce25e8d458a21130879b840a"
                             "9089d999aaba039eaf3e3afa090a09d3"
                             "89dba82c4ff2ae8ac5cdfb7c55e94d5d"
                             "961a29fe0109941e00b8dbdeea6d3b05"
                             "1068df7254c0cdc129cbe62db2dc957d"
                             "bb47b51fd3f213fb8698f064774250a5"
                             "028961c9bf8ffd973fe5d5c206492b14"
                             "0e00")],
        ),
        ed448_group(
            pk="3ba16da0c6f2cc1f30187740756f5e79"
               "8d6bc5fc015d7c63cc9510ee3fd44adc"
               "24d8e968b6e46e6f94d19b945361726b"
               "d75e149ef09817f580",
            tests=[tc448(10, "RFC 8032 7.4 12 octets",
                         msg="64a65f3cdedcdd66811e2915",
                         sig="7eeeab7c4e50fb799b418ee5e3197ff6"
                             "bf15d43a14c34389b59dd1a7b1b85b4a"
                             "e90438aca634bea45e3a2695f1270f07"
                             "fdcdf7c62b8efeaf00b45c2c96ba457e"
                             "b1a8bf075a3db28e5c24f6b923ed4ad7"
                             "47c3c9e03c7079efb87cb110d3a99861"
                             "e72003cbae6d6b8b827e4e6c143064ff"
                             "3c00")],
        ),
        ed448_group(
            pk="b3da079b0aa493a5772029f0467baebe"
               "e5a8112d9d3a22532361da294f7bb381"
               "5c5dc59e176b4d9f381ca0938e13c6c0"
               "7b174be65dfa578e80",
            tests=[tc448(11, "RFC 8032 7.4 13 octets",
                         msg="64a65f3cdedcdd66811e2915e7",
                         sig="6a12066f55331b6c22acd5d5bfc5d712"
                             "28fbda80ae8dec26bdd306743c5027cb"
                             "4890810c162c027468675ecf645a8317"
                             "6c0d7323a2ccde2d80efe5a1268e8aca"
                             "1d6fbc194d3f77c44986eb4ab4177919"
                             "ad8bec33eb47bbb5fc6e28196fd1caf5"
                             "6b4e7e0ba5519234d047155ac727a105"
                             "3100")],
        ),
        ed448_group(
            pk="df9705f58edbab802c7f8363cfe5560a"
               "b1c6132c20a9f1dd163483a26f8ac53a"
               "39d6808bf4a1dfbd261b099bb03b3fb5"
               "0906cb28bd8a081f00",
            tests=[tc448(12, "RFC 8032 7.4 64 octets",
                         msg="bd0f6a3747cd561bdddf4640a332461a"
                             "4a30a12a434cd0bf40d766d9c6d458e5"
                             "512204a30c17d1f50b5079631f64eb31"
                             "12182da3005835461113718d1a5ef944",
                         sig="554bc2480860b49eab8532d2a533b7d5"
                             "78ef473eeb58c98bb2d0e1ce488a98b1"
                             "8dfde9b9b90775e67f47d4a1c3482058"
                             "efc9f40d2ca033a0801b63d45b3b722e"
                             "f552bad3b4ccb667da350192b61c508c"
                             "f7b6b5adadc2c8d9a446ef003fb05cba"
                             "5f30e88e36ec2703b349ca229c267083"
                             "3900")],
        ),
        ed448_group(
            pk="79756f014dcfe2079f5dd9e718be4171"
               "e2ef2486a08f25186f6bff43a9936b9b"
               "fe12402b08ae65798a3d81e22e9ec80e"
               "7690862ef3d4ed3a00",
            tests=[tc448(13, "RFC 8032 7.4 256 octets",
                         msg="15777532b0bdd0d1389f636c5f6b9ba7"
                             "34c90af572877e2d272dd078aa1e567c"
                             "fa80e12928bb542330e8409f31745041"
                             "07ecd5efac61ae7504dabe2a602ede89"
                             "e5cca6257a7c77e27a702b3ae39fc769"
                             "fc54f2395ae6a1178cab4738e543072f"
                             "c1c177fe71e92e25bf03e4ecb72f47b6"
                             "4d0465aaea4c7fad372536c8ba516a60"
                             "39c3c2a39f0e4d832be432dfa9a706a6"
                             "e5c7e19f397964ca4258002f7c0541b5"
                             "90316dbc5622b6b2a6fe7a4abffd9610"
                             "5eca76ea7b98816af0748c10df048ce0"
                             "12d901015a51f189f3888145c03650aa"
                             "23ce894c3bd889e030d565071c59f409"
                             "a9981b51878fd6fc110624dcbcde0bf7"
                             "a69ccce38fabdf86f3bef6044819de11",
                         sig="c650ddbb0601c19ca11439e1640dd931"
                             "f43c518ea5bea70d3dcde5f4191fe53f"
                             "00cf966546b72bcc7d58be2b9badef28"
                             "743954e3a44a23f880e8d4f1cfce2d7a"
                             "61452d26da05896f0a50da66a239a8a1"
                             "88b6d825b3305ad77b73fbac0836ecc6"
                             "0987fd08527c1a8e80d5823e65cafe2a"
                             "3d00")],
        ),
        ed448_group(
            pk="a81b2e8a70a5ac94ffdbcc9badfc3feb"
               "0801f258578bb114ad44ece1ec0e799d"
               "a08effb81c5d685c0c56f64eecaef8cd"
               "f11cc38737838cf400",
            tests=[tc448(14, "RFC 8032 7.4 1023 octets",
                         msg="6ddf802e1aae4986935f7f981ba3f035"
                             "1d6273c0a0c22c9c0e8339168e675412"
                             "a3debfaf435ed651558007db4384b650"
                             "fcc07e3b586a27a4f7a00ac8a6fec2cd"
                             "86ae4bf1570c41e6a40c931db27b2faa"
                             "15a8cedd52cff7362c4e6e23daec0fbc"
                             "3a79b6806e316efcc7b68119bf46bc76"
                             "a26067a53f296dafdbdc11c77f7777e9"
                             "72660cf4b6a9b369a6665f02e0cc9b6e"
                             "dfad136b4fabe723d2813db3136cfde9"
                             "b6d044322fee2947952e031b73ab5c60"
                             "3349b307bdc27bc6cb8b8bbd7bd32321"
                             "9b8033a581b59eadebb09b3c4f3d2277"
                             "d4f0343624acc817804728b25ab79717"
                             "2b4c5c21a22f9c7839d64300232eb66e"
                             "53f31c723fa37fe387c7d3e50bdf9813"
                             "a30e5bb12cf4cd930c40cfb4e1fc6225"
                             "92a49588794494d56d24ea4b40c89fc0"
                             "596cc9ebb961c8cb10adde976a5d602b"
                             "1c3f85b9b9a001ed3c6a4d3b1437f520"
                             "96cd1956d042a597d561a596ecd3d173"
                             "5a8d570ea0ec27225a2c4aaff26306d1"
                             "526c1af3ca6d9cf5a2c98f47e1c46db9"
                             "a33234cfd4d81f2c98538a09ebe76998"
                             "d0d8fd25997c7d255c6d66ece6fa56f1"
                             "1144950f027795e653008f4bd7ca2dee"
                             "85d8e90f3dc315130ce2a00375a318c7"
                             "c3d97be2c8ce5b6db41a6254ff264fa6"
                             "155baee3b0773c0f497c573f19bb4f42"
                             "40281f0b1f4f7be857a4e59d416c06b4"
                             "c50fa09e1810ddc6b1467baeac5a3668"
                             "d11b6ecaa901440016f389f80acc4db9"
                             "77025e7f5924388c7e340a732e554440"
                             "e76570f8dd71b7d640b3450d1fd5f041"
                             "0a18f9a3494f707c717b79b4bf75c984"
                             "00b096b21653b5d217cf3565c9597456"
                             "f70703497a078763829bc01bb1cbc8fa"
                             "04eadc9a6e3f6699587a9e75c94e5bab"
                             "0036e0b2e711392cff0047d0d6b05bd2"
                             "a588bc109718954259f1d86678a579a3"
                             "120f19cfb2963f177aeb70f2d4844826"
                             "262e51b80271272068ef5b3856fa8535"
                             "aa2a88b2d41f2a0e2fda7624c2850272"
                             "ac4a2f561f8f2f7a318bfd5caf969614"
                             "9e4ac824ad3460538fdc25421beec2cc"
                             "6818162d06bbed0c40a387192349db67"
                             "a118bada6cd5ab0140ee273204f628aa"
                             "d1c135f770279a651e24d8c14d75a605"
                             "9d76b96a6fd857def5e0b354b27ab937"
                             "a5815d16b5fae407ff18222c6d1ed263"
                             "be68c95f32d908bd895cd76207ae7264"
                             "87567f9a67dad79abec316f683b17f2d"
                             "02bf07e0ac8b5bc6162cf94697b3c27c"
                             "d1fea49b27f23ba2901871962506520c"
                             "392da8b6ad0d99f7013fbc06c2c17a56"
                             "9500c8a7696481c1cd33e9b14e40b82e"
                             "79a5f5db82571ba97bae3ad3e0479515"
                             "bb0e2b0f3bfcd1fd33034efc6245eddd"
                             "7ee2086ddae2600d8ca73e214e8c2b0b"
                             "db2b047c6a464a562ed77b73d2d841c4"
                             "b34973551257713b753632efba348169"
                             "abc90a68f42611a40126d7cb21b58695"
                             "568186f7e569d2ff0f9e745d0487dd2e"
                             "b997cafc5abf9dd102e62ff66cba87",
                         sig="e301345a41a39a4d72fff8df69c98075"
                             "a0cc082b802fc9b2b6bc503f926b65bd"
                             "df7f4c8f1cb49f6396afc8a70abe6d8a"
                             "ef0db478d4c6b2970076c6a0484fe76d"
                             "76b3a97625d79f1ce240e7c576750d29"
                             "5528286f719b413de9ada3e8eb78ed57"
                             "3603ce30d8bb761785dc30dbc320869e"
                             "1a00")],
        ),
    ]

    n = sum(len(g["tests"]) for g in groups)
    return {
        "algorithm": "EDDSA",
        "schema": "eddsa_verify_schema_v1.json",
        "numberOfTests": n,
        "header": ["RFC 8032 EdDSA test vectors"],
        "notes": {},
        "testGroups": groups,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"Writing to {OUTPUT_DIR}/")
    write_json("rfc8439_chacha20poly1305_test.json", make_rfc8439())
    write_json("rfc3394_aeskw_test.json",            make_rfc3394())
    write_json("rfc7748_x25519_test.json",           make_rfc7748_x25519())
    write_json("rfc7748_x448_test.json",             make_rfc7748_x448())
    write_json("rfc5869_hkdf_test.json",             make_rfc5869())
    write_json("rfc8032_eddsa_test.json",            make_rfc8032())
    print("Done.")


if __name__ == "__main__":
    main()
