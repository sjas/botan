/*
* (C) 2010,2014,2015 Jack Lloyd
* (C) 2015 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

#include <botan/base64.h>

#include <botan/pk_keys.h>
#include <botan/x509_key.h>
#include <botan/pk_algs.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>

#if defined(BOTAN_HAS_DL_GROUP)
   #include <botan/dl_group.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
#endif

namespace Botan_CLI {

class PK_Fingerprint final : public Command
   {
   public:
      PK_Fingerprint() : Command("fingerprint --algo=SHA-256 *keys") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string short_description() const override
         {
         return "Calculate a public key fingerprint";
         }

      std::string long_description() const override
         {
         return "TODO";
         }

      void go() override
         {
         const std::string hash_algo = get_arg("algo");

         for(std::string key_file : get_arg_list("keys"))
            {
            std::unique_ptr<Botan::Public_Key> key(Botan::X509::load_key(key_file));

            output() << key_file << ": " << key->fingerprint_public(hash_algo) << "\n";
            }
         }
   };

BOTAN_REGISTER_COMMAND("fingerprint", PK_Fingerprint);

class PK_Keygen final : public Command
   {
   public:
      PK_Keygen() : Command("keygen --algo=RSA --params= --passphrase= --pbe= --pbe-millis=300 --der-out") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string short_description() const override
         {
         return "Generate a PKCS #8 private key";
         }

      std::string long_description() const override
         {
         return "Generate a PKCS #8 algo private key. If der-out is passed, the pair is BER encoded."
               "Otherwise, PEM encoding is used. To protect the PKCS #8 formatted key, "
               "it is recommended to encrypt it with a provided passphrase. "
               "pbe is the name of the desired encryption algorithm, which uses pbe-millis milliseconds "
               "to derive the encryption key from the passed passphrase. Algorithm specific parameters, "
               "as the desired bitlength of an RSA key, can be passed with params.\n\n"
               "For RSA params specifies the bit length of the RSA modulus. It defaults to 3072.\n"
               "For DH params specifies the DH parameters. It defaults to modp/ietf/2048.\n"
               "For DSA params specifies the DSA parameters. It defaults to dsa/botan/2048.\n"
               "For EC algorithms params specifies the elliptic curve. It defaults to secp256r1.";
         }

      void go() override
         {
         const std::string algo = get_arg("algo");
         const std::string params = get_arg("params");

         std::unique_ptr<Botan::Private_Key>
         key(Botan::create_private_key(algo, rng(), params));

         if(!key)
            {
            throw CLI_Error_Unsupported("keygen", algo);
            }

         const std::string pass = get_arg("passphrase");
         const bool der_out = flag_set("der-out");

         const std::chrono::milliseconds pbe_millis(get_arg_sz("pbe-millis"));
         const std::string pbe = get_arg("pbe");

         if(der_out)
            {
            if(pass.empty())
               {
               write_output(Botan::PKCS8::BER_encode(*key));
               }
            else
               {
               write_output(Botan::PKCS8::BER_encode(*key, rng(), pass, pbe_millis, pbe));
               }
            }
         else
            {
            if(pass.empty())
               {
               output() << Botan::PKCS8::PEM_encode(*key);
               }
            else
               {
               output() << Botan::PKCS8::PEM_encode(*key, rng(), pass, pbe_millis, pbe);
               }
            }
         }
   };

BOTAN_REGISTER_COMMAND("keygen", PK_Keygen);

namespace {

std::string algo_default_emsa(const std::string& key)
   {
   if(key == "RSA")
      {
      return "EMSA4";
      } // PSS
   else if(key == "ECDSA" || key == "DSA")
      {
      return "EMSA1";
      }
   else
      {
      return "EMSA1";
      }
   }

}

class PK_Sign final : public Command
   {
   public:
      PK_Sign() : Command("sign --passphrase= --hash=SHA-256 --emsa= key file") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string short_description() const override
         {
         return "Sign arbitrary data";
         }

      std::string long_description() const override
         {
         return "Sign the data in file using the PKCS #8 private key *key*. "
               "If key is encrypted, the used passphrase must be passed as *pass-in*. "
               "*emsa* specifies the signature scheme and *hash* the cryptographic hash "
               "function used in the scheme.\n\n"
               "For RSA signatures EMSA4 (RSA-PSS) is the default scheme.\n"
               "For ECDSA and DSA emsa defaults to EMSA1.";
         }

      void go() override
         {
         std::unique_ptr<Botan::Private_Key> key(
            Botan::PKCS8::load_key(
               get_arg("key"),
               rng(),
               get_arg("passphrase")));

         if(!key)
            {
            throw CLI_Error("Unable to load private key");
            }

         const std::string sig_padding =
            get_arg_or("emsa", algo_default_emsa(key->algo_name())) + "(" + get_arg("hash") + ")";

         Botan::PK_Signer signer(*key, rng(), sig_padding);

         auto onData = [&signer](const uint8_t b[], size_t l)
            {
            signer.update(b, l);
            };
         this->read_file(get_arg("file"), onData);

         output() << Botan::base64_encode(signer.signature(rng())) << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("sign", PK_Sign);

class PK_Verify final : public Command
   {
   public:
      PK_Verify() : Command("verify --hash=SHA-256 --emsa= pubkey file signature") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string short_description() const override
         {
         return "Verify the authenticity of the given file with the provided signature";
         }

      std::string long_description() const override
         {
         return "";
         }

      void go() override
         {
         std::unique_ptr<Botan::Public_Key> key(Botan::X509::load_key(get_arg("pubkey")));
         if(!key)
            {
            throw CLI_Error("Unable to load public key");
            }

         const std::string sig_padding =
            get_arg_or("emsa", algo_default_emsa(key->algo_name())) + "(" + get_arg("hash") + ")";

         Botan::PK_Verifier verifier(*key, sig_padding);
         auto onData = [&verifier](const uint8_t b[], size_t l)
            {
            verifier.update(b, l);
            };
         this->read_file(get_arg("file"), onData);

         const Botan::secure_vector<uint8_t> signature =
            Botan::base64_decode(this->slurp_file_as_str(get_arg("signature")));

         const bool valid = verifier.check_signature(signature);

         output() << "Signature is " << (valid ? "valid" : "invalid") << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("verify", PK_Verify);

#if defined(BOTAN_HAS_ECC_GROUP)

class EC_Group_Info final : public Command
   {
   public:
      EC_Group_Info() : Command("ec_group_info --pem name") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string short_description() const override
         {
         return "Print raw elliptic curve domain parameters of the standarized curve name";
         }

      std::string long_description() const override
         {
         return "Print raw elliptic curve domain parameters of the standarized curve name. "
               "If pem is set, the encoded domain is printed.";
         }

      void go() override
         {
         Botan::EC_Group group(get_arg("name"));

         if(flag_set("pem"))
            {
            output() << group.PEM_encode();
            }
         else
            {
            output() << "P = " << std::hex << group.get_curve().get_p() << "\n"
                     << "A = " << std::hex << group.get_curve().get_a() << "\n"
                     << "B = " << std::hex << group.get_curve().get_b() << "\n"
                     << "G = " << group.get_base_point().get_affine_x() << ","
                     << group.get_base_point().get_affine_y() << "\n";
            }

         }
   };

BOTAN_REGISTER_COMMAND("ec_group_info", EC_Group_Info);

#endif

#if defined(BOTAN_HAS_DL_GROUP)

class DL_Group_Info final : public Command
   {
   public:
      DL_Group_Info() : Command("dl_group_info --pem name") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string short_description() const override
         {
         return "Print raw Diffie-Hellman parameters (p,g) of the standarized DH group name";
         }

      std::string long_description() const override
         {
         return "Print raw Diffie-Hellman parameters (p,g) of the standarized DH group name. "
               "If pem is set, the X9.42 encoded group is printed.";
         }

      void go() override
         {
         Botan::DL_Group group(get_arg("name"));

         if(flag_set("pem"))
            {
            output() << group.PEM_encode(Botan::DL_Group::ANSI_X9_42_DH_PARAMETERS);
            }
         else
            {
            output() << "P = " << std::hex << group.get_p() << "\n"
                     << "G = " << group.get_g() << "\n";
            }

         }
   };

BOTAN_REGISTER_COMMAND("dl_group_info", DL_Group_Info);

class Gen_DL_Group final : public Command
   {
   public:
      Gen_DL_Group() : Command("gen_dl_group --pbits=1024 --qbits=0 --type=subgroup") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string short_description() const override
         {
         return "Generate ANSI X9.42 encoded Diffie-Hellman group parameters";
         }

      std::string long_description() const override
         {
         return "Generate ANSI X9.42 encoded Diffie-Hellman group parameters. "
               "If type=subgroup is passed, the size of the prime subgroup q "
               "is sampled as a prime of qbits length and p is pbits long. "
               "If qbits is not passed, its length is estimated from pbits as described in RFC 3766. "
               "If type=strong is passed, p is sampled as a safe prime with length pbits "
               "and the prime subgroup has size q with pbits-1 length.";
         }

      void go() override
         {
         const size_t pbits = get_arg_sz("pbits");

         const std::string type = get_arg("type");

         if(type == "strong")
            {
            Botan::DL_Group grp(rng(), Botan::DL_Group::Strong, pbits);
            output() << grp.PEM_encode(Botan::DL_Group::ANSI_X9_42);
            }
         else if(type == "subgroup")
            {
            Botan::DL_Group grp(rng(), Botan::DL_Group::Prime_Subgroup, pbits, get_arg_sz("qbits"));
            output() << grp.PEM_encode(Botan::DL_Group::ANSI_X9_42);
            }
         else
            {
            throw CLI_Usage_Error("Invalid DL type '" + type + "'");
            }
         }
   };

BOTAN_REGISTER_COMMAND("gen_dl_group", Gen_DL_Group);

#endif

class PKCS8_Tool final : public Command
   {
   public:
      PKCS8_Tool() : Command("pkcs8 --pass-in= --pub-out --der-out --pass-out= --pbe= --pbe-millis=300 key") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string short_description() const override
         {
         return "Open a PKCS #8 formatted key";
         }

      std::string long_description() const override
         {
         return "Open a PKCS #8 formatted key at *key*. "
               "If key is encrypted, the passphrase must be passed as *pass-in*. "
               "It is possible to (re)encrypt the read key with the passphrase passed as *pass-out*. "
               "The parameters *pbe-millis* and *pbe* work similarly to *keygen*.";
         }

      void go() override
         {
         std::unique_ptr<Botan::Private_Key> key;
         std::string pass_in = get_arg("pass-in");

         if (pass_in.empty())
         {
            key.reset(Botan::PKCS8::load_key(get_arg("key"), rng()));
         }
         else
         {
            key.reset(Botan::PKCS8::load_key(get_arg("key"), rng(), pass_in));
         }

         const std::chrono::milliseconds pbe_millis(get_arg_sz("pbe-millis"));
         const std::string pbe = get_arg("pbe");
         const bool der_out = flag_set("der-out");

         if(flag_set("pub-out"))
            {
            if(der_out)
               {
               write_output(Botan::X509::BER_encode(*key));
               }
            else
               {
               output() << Botan::X509::PEM_encode(*key);
               }
            }
         else
            {
            const std::string pass_out = get_arg("pass-out");

            if(der_out)
               {
               if(pass_out.empty())
                  {
                  write_output(Botan::PKCS8::BER_encode(*key));
                  }
               else
                  {
                  write_output(Botan::PKCS8::BER_encode(*key, rng(), pass_out, pbe_millis, pbe));
                  }
               }
            else
               {
               if(pass_out.empty())
                  {
                  output() << Botan::PKCS8::PEM_encode(*key);
                  }
               else
                  {
                  output() << Botan::PKCS8::PEM_encode(*key, rng(), pass_out, pbe_millis, pbe);
                  }
               }
            }
         }
   };

BOTAN_REGISTER_COMMAND("pkcs8", PKCS8_Tool);

}

#endif
