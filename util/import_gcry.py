#*
#*  GRUB  --  GRand Unified Bootloader
#*  Copyright (C) 2009  Free Software Foundation, Inc.
#*
#*  GRUB is free software: you can redistribute it and/or modify
#*  it under the terms of the GNU General Public License as published by
#*  the Free Software Foundation, either version 3 of the License, or
#*  (at your option) any later version.
#*
#*  GRUB is distributed in the hope that it will be useful,
#*  but WITHOUT ANY WARRANTY; without even the implied warranty of
#*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#*  GNU General Public License for more details.
#*
#*  You should have received a copy of the GNU General Public License
#*  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
#*

import re
import sys
import os
import datetime
import codecs

if len (sys.argv) < 3:
    print ("Usage: %s SOURCE DESTINATION" % sys.argv[0])
    exit (0)
indir = sys.argv[1]
outdir = sys.argv[2]

basedir = os.path.join (outdir, "lib/libgcrypt-grub")
try:
    os.makedirs (basedir)
except:
    print ("WARNING: %s already exists" % basedir)
cipher_dir_in = os.path.join (indir, "cipher")
cipher_dir_out = os.path.join (basedir, "cipher")
mpi_dir_in = os.path.join (indir, "mpi")
mpi_dir_out = os.path.join (basedir, "mpi")
try:
    os.makedirs (cipher_dir_out)
    os.makedirs (mpi_dir_out)
except:
    print ("WARNING: %s already exists" % cipher_dir_out)

cipher_files = sorted (os.listdir (cipher_dir_in))
mpi_files = sorted (os.listdir (mpi_dir_in))
conf = codecs.open (os.path.join ("grub-core", "Makefile.gcry.def"), "w", "utf-8")
conf.write ("AutoGen definitions Makefile.tpl;\n\n")
confutil = codecs.open ("Makefile.utilgcry.def", "w", "utf-8")
confutil.write ("AutoGen definitions Makefile.tpl;\n\n")
confutil.write ("library = {\n");
confutil.write ("  name = libgrubgcry.a;\n");
confutil.write ("  cflags = '$(CFLAGS_GCRY)';\n");
confutil.write ("  cppflags = '$(CPPFLAGS_GCRY)';\n");
confutil.write ("  extra_dist = grub-core/lib/libgcrypt-grub/cipher/ChangeLog;\n");
confutil.write ("\n");
chlog = ""
modules = []

# Strictly speaking CRC32/CRC24 work on bytes so this value should be 1
# But libgcrypt uses 64. Let's keep the value for compatibility. Since
# noone uses CRC24/CRC32 for HMAC this is no problem
mdblocksizes = {"_gcry_digest_spec_crc32" : 64,
                "_gcry_digest_spec_crc32_rfc1510" : 64,
                "_gcry_digest_spec_crc24_rfc2440" : 64,
                "_gcry_digest_spec_md4" : 64,
                "_gcry_digest_spec_md5" : 64,
                "_gcry_digest_spec_rmd160" : 64,
                "_gcry_digest_spec_sha1" : 64,
                "_gcry_digest_spec_sha224" : 64,
                "_gcry_digest_spec_sha256" : 64,
                "_gcry_digest_spec_sha384" : 128,
                "_gcry_digest_spec_sha512" : 128,
                "_gcry_digest_spec_tiger" : 64,
                "_gcry_digest_spec_whirlpool" : 64}

cryptolist = codecs.open (os.path.join (cipher_dir_out, "crypto.lst"), "w", "utf-8")

# rijndael is the only cipher using aliases. So no need for mangling, just
# hardcode it
cryptolist.write ("RIJNDAEL: gcry_rijndael\n");
cryptolist.write ("RIJNDAEL192: gcry_rijndael\n");
cryptolist.write ("RIJNDAEL256: gcry_rijndael\n");
cryptolist.write ("AES128: gcry_rijndael\n");
cryptolist.write ("AES-128: gcry_rijndael\n");
cryptolist.write ("AES-192: gcry_rijndael\n");
cryptolist.write ("AES-256: gcry_rijndael\n");

cryptolist.write ("ADLER32: adler32\n");
cryptolist.write ("CRC64: crc64\n");

for mpi_file in mpi_files:
    infile = os.path.join (mpi_dir_in, mpi_file)
    outfile = os.path.join (mpi_dir_out, mpi_file)
    if mpi_file == "ChangeLog":
        continue
    chlognew = "	* %s" % mpi_file
    nch = False
    if re.match (".*\.[ch]$", mpi_file):
        isc = re.match (".*\.c$", mpi_file)
        f = codecs.open (infile, "r", "utf-8")
        fw = codecs.open (outfile, "w", "utf-8")
        fw.write ("/* This file was automatically imported with \n")
        fw.write ("   import_gcry.py. Please don't modify it */\n")
        fw.write ("#include <grub/dl.h>\n")
        # Whole libgcrypt is distributed under GPLv3+ or compatible
        if isc:
            fw.write ("GRUB_MOD_LICENSE (\"GPLv3+\");\n")
            modname = mpi_file [0:len(mpi_file) - 2]
            if re.match (".*-glue$", modname):
                modname = modname.replace ("-glue", "")
                isglue = True
            modname = "gcry_%s" % modname
        for line in f:
            m = re.match ("# *include <(.*)>", line)
            if m is not None:
                chmsg = "Removed including of %s" % m.groups ()[0]
                if nch:
                    chlognew = "%s\n	%s" % (chlognew, chmsg)
                else:
                    chlognew = "%s: %s" % (chlognew, chmsg)
                    nch = True
                m = re.match ("# *include \"(mpi-asm-defs.h)\"", line)
                if m is not None:
                    fw.write('#include <cipher_wrap.h>')
                continue
            fw.write (line)
        if isc:
            conf.write ("module = {\n")
            conf.write ("  name = %s;\n" % modname)
            modfiles = "lib/libgcrypt-grub/mpi/%s" % mpi_file
            for src in modfiles.split():
                conf.write ("  common = %s;\n" % src)
                confutil.write ("  common = grub-core/%s;\n" % src)
            conf.write ("  cflags = '$(CFLAGS_GCRY)';\n");
            conf.write ("  cppflags = '$(CPPFLAGS_GCRY)';\n");
            conf.write ("};\n\n")
            f.close ()
            fw.close ()
            if nch:
                chlog = "%s%s\n" % (chlog, chlognew)
        else:
            print ("WARNING: what is %s" % mpi_file)
            f.close ()
            fw.close ()
            chlog = "%s\n	* %s: Confused" % (chlog, mpi_file)
    chlog = "%s%sSkipped unknown file\n" % (chlog, chlognew)
    print ("WARNING: unknown file %s" % mpi_file)

for cipher_file in cipher_files:
    infile = os.path.join (cipher_dir_in, cipher_file)
    outfile = os.path.join (cipher_dir_out, cipher_file)
    if cipher_file == "ChangeLog":
        continue
    chlognew = "	* %s" % cipher_file
    if re.match ("(Manifest|Makefile\.am|ac\.c|cipher\.c|hash-common\.c|hmac-tests\.c|md\.c|pubkey\.c|ecc\.c)$", cipher_file):
        chlog = "%s%s: Removed\n" % (chlog, chlognew)
        continue
    # Autogenerated files. Not even worth mentionning in ChangeLog
    if re.match ("Makefile\.in$", cipher_file):
        continue
    nch = False
    if re.match (".*\.[ch]$", cipher_file):
        isc = re.match (".*\.c$", cipher_file)
        f = codecs.open (infile, "r", "utf-8")
        fw = codecs.open (outfile, "w", "utf-8")
        fw.write ("/* This file was automatically imported with \n")
        fw.write ("   import_gcry.py. Please don't modify it */\n")
        fw.write ("#include <grub/dl.h>\n")
        if cipher_file == "camellia.h":
            fw.write ("#include <grub/misc.h>\n")
            fw.write ("void camellia_setup128(const unsigned char *key, grub_uint32_t *subkey);\n")
            fw.write ("void camellia_setup192(const unsigned char *key, grub_uint32_t *subkey);\n")
            fw.write ("void camellia_setup256(const unsigned char *key, grub_uint32_t *subkey);\n")
            fw.write ("void camellia_encrypt128(const grub_uint32_t *subkey, grub_uint32_t *io);\n")
            fw.write ("void camellia_encrypt192(const grub_uint32_t *subkey, grub_uint32_t *io);\n")                      
            fw.write ("void camellia_encrypt256(const grub_uint32_t *subkey, grub_uint32_t *io);\n")                      
            fw.write ("void camellia_decrypt128(const grub_uint32_t *subkey, grub_uint32_t *io);\n")
            fw.write ("void camellia_decrypt192(const grub_uint32_t *subkey, grub_uint32_t *io);\n")                      
            fw.write ("void camellia_decrypt256(const grub_uint32_t *subkey, grub_uint32_t *io);\n")                      
            fw.write ("#define memcpy grub_memcpy\n")
        # Whole libgcrypt is distributed under GPLv3+ or compatible
        if isc:
            fw.write ("GRUB_MOD_LICENSE (\"GPLv3+\");\n")

        ciphernames = []
        mdnames = []
        pknames = []
        hold = False
        skip = False
        skip2 = False
        ismd = False
        iscipher = False
        ispk = False
        iscryptostart = False
        iscomma = False
        isglue = False
        skip_statement = False
        if isc:
            modname = cipher_file [0:len(cipher_file) - 2]
            if re.match (".*-glue$", modname):
                modname = modname.replace ("-glue", "")
                isglue = True
            modname = "gcry_%s" % modname
        for line in f:
            line = line
            if skip_statement:
                if re.search (";", line) is not None:
                    skip_statement = False
                continue
            if skip:
                if line[0] == "}":
                    skip = False
                continue
            if skip2:
                if re.search (" *};", line) is not None:
                    skip2 = False
                continue
            if iscryptostart:
                s = re.search (" *\"([A-Z0-9_a-z]*)\"", line)
                if s is not None:
                    sg = s.groups()[0]
                    cryptolist.write (("%s: %s\n") % (sg, modname))
                    iscryptostart = False
            if ismd or iscipher or ispk:
                if re.search (" *};", line) is not None:
                    if not iscomma:
                        fw.write ("    ,\n")
                    fw.write ("#ifdef GRUB_UTIL\n");
                    fw.write ("    .modname = \"%s\",\n" % modname);
                    fw.write ("#endif\n");
                    if ismd:
                        if mdname not in mdblocksizes:
                            print ("ERROR: Unknown digest blocksize: %s\n"
                                   % mdname)
                            exit (1)
                        fw.write ("    .blocksize = %s\n"
                                  % mdblocksizes [mdname])
                    ismd = False
                    iscipher = False
                    ispk = False
                iscomma = not re.search (",$", line) is None
            # Used only for selftests.
            m = re.match ("(static byte|static unsigned char) (weak_keys_chksum)\[[0-9]*\] =", line)
            if m is not None:
                skip = True
                fname = m.groups ()[1]
                chmsg = "(%s): Removed." % fname
                if nch:
                    chlognew = "%s\n	%s" % (chlognew, chmsg)
                else:
                    chlognew = "%s %s" % (chlognew, chmsg)
                    nch = True
                continue
            if hold:
                hold = False
                # We're optimising for size.
                if re.match ("(run_selftests|selftest|_gcry_aes_c.._..c|_gcry_[a-z0-9]*_hash_buffer|tripledes_set2keys|do_tripledes_set_extra_info|_gcry_rmd160_mixblock|serpent_test)", line) is not None:
                    skip = True
                    if re.match ("serpent_test", line) is not None:
                        fw.write ("static const char *serpent_test (void) { return 0; }\n");
                    fname = re.match ("[a-zA-Z0-9_]*", line).group ()
                    chmsg = "(%s): Removed." % fname
                    if nch:
                        chlognew = "%s\n	%s" % (chlognew, chmsg)
                    else:
                        chlognew = "%s %s" % (chlognew, chmsg)
                        nch = True
                    continue
                else:
                    fw.write (holdline)
            m = re.match ("# *include <(.*)>", line)
            if m is not None:
                chmsg = "Removed including of %s" % m.groups ()[0]
                if nch:
                    chlognew = "%s\n	%s" % (chlognew, chmsg)
                else:
                    chlognew = "%s: %s" % (chlognew, chmsg)
                    nch = True
                continue
            m = re.match ("gcry_cipher_spec_t", line)
            if isc and m is not None:
                assert (not ismd)
                assert (not iscipher)
                assert (not ispk)
                assert (not iscryptostart)
                ciphername = line [len ("gcry_cipher_spec_t"):].strip ()
                ciphername = re.match("[a-zA-Z0-9_]*",ciphername).group ()
                ciphernames.append (ciphername)
                iscipher = True
                iscryptostart = True
            m = re.match ("gcry_md_spec_t", line)
            if isc and m is not None:
                assert (not ismd)
                assert (not iscipher)
                assert (not ispk)
                assert (not iscryptostart)
                mdname = line [len ("gcry_md_spec_t"):].strip ()
                mdname = re.match("[a-zA-Z0-9_]*",mdname).group ()
                mdnames.append (mdname)
                ismd = True
                iscryptostart = True
            m = re.match ("gcry_pk_spec_t", line)
            if isc and m is not None:
                assert (not ismd)
                assert (not iscipher)
                assert (not ispk)
                assert (not iscryptostart)
                pkname = line [len ("gcry_pk_spec_t"):].strip ()
                pkname = re.match("[a-zA-Z0-9_]*",mdname).group ()
                pknames.append (pkname)
                ispk = True
                iscryptostart = True
            m = re.match ("static const char \*selftest.*;$", line)
            if m is not None:
                fname = line[len ("static const char \*"):]
                fname = re.match ("[a-zA-Z0-9_]*", fname).group ()
                chmsg = "(%s): Removed declaration." % fname
                if nch:
                    chlognew = "%s\n	%s" % (chlognew, chmsg)
                else:
                    chlognew = "%s %s" % (chlognew, chmsg)
                    nch = True
                continue
            m = re.match ("(static const char( |)\*|static gpg_err_code_t|void|static int|static gcry_err_code_t)$", line)
            if m is not None:
                hold = True
                holdline = line
                continue
            m = re.match ("static int tripledes_set2keys \(.*\);", line)
            if m is not None:
                continue
            m = re.match ("static int tripledes_set2keys \(", line)
            if m is not None:
                skip_statement = True
                continue
            m = re.match ("cipher_extra_spec_t", line)
            if isc and m is not None:
                skip2 = True
                fname = line[len ("cipher_extra_spec_t "):]
                fname = re.match ("[a-zA-Z0-9_]*", fname).group ()
                chmsg = "(%s): Removed." % fname
                if nch:
                    chlognew = "%s\n	%s" % (chlognew, chmsg)
                else:
                    chlognew = "%s %s" % (chlognew, chmsg)
                    nch = True
                continue
            m = re.match ("md_extra_spec_t", line)
            if isc and m is not None:
                skip2 = True
                fname = line[len ("md_extra_spec_t "):]
                fname = re.match ("[a-zA-Z0-9_]*", fname).group ()
                chmsg = "(%s): Removed." % fname
                if nch:
                    chlognew = "%s\n	%s" % (chlognew, chmsg)
                else:
                    chlognew = "%s %s" % (chlognew, chmsg)
                    nch = True
                continue
            m = re.match ("pk_extra_spec_t", line)
            if isc and m is not None:
                skip2 = True
                fname = line[len ("pk_extra_spec_t "):]
                fname = re.match ("[a-zA-Z0-9_]*", fname).group ()
                chmsg = "(%s): Removed." % fname
                if nch:
                    chlognew = "%s\n	%s" % (chlognew, chmsg)
                else:
                    chlognew = "%s %s" % (chlognew, chmsg)
                    nch = True
                continue
            fw.write (line)
        if len (ciphernames) > 0 or len (mdnames) > 0 or len (pknames) > 0:
            if isglue:
                modfiles = "lib/libgcrypt-grub/cipher/%s lib/libgcrypt-grub/cipher/%s" \
                    % (cipher_file, cipher_file.replace ("-glue.c", ".c"))
            else:
                modfiles = "lib/libgcrypt-grub/cipher/%s" % cipher_file
            modules.append (modname)
            chmsg = "(GRUB_MOD_INIT(%s)): New function\n" % modname
            if nch:
                chlognew = "%s\n	%s" % (chlognew, chmsg)
            else:
                chlognew = "%s%s" % (chlognew, chmsg)
                nch = True
            fw.write ("\n\nGRUB_MOD_INIT(%s)\n" % modname)
            fw.write ("{\n")
            for ciphername in ciphernames:
                chmsg = "Register cipher %s" % ciphername
                chlognew = "%s\n	%s" % (chlognew, chmsg)
                fw.write ("  grub_cipher_register (&%s);\n" % ciphername)
            for mdname in mdnames:
                chmsg = "Register digest %s" % mdname
                chlognew = "%s\n	%s" % (chlognew, chmsg)
                fw.write ("  grub_md_register (&%s);\n" % mdname)
            for pkname in pknames:
                chmsg = "Register algorithm %s" % pkname
                chlognew = "%s\n	%s" % (chlognew, chmsg)
                fw.write ("  grub_pk_register (&%s);\n" % pkname)
            fw.write ("}")
            chmsg = "(GRUB_MOD_FINI(%s)): New function\n" % modname
            chlognew = "%s\n	%s" % (chlognew, chmsg)
            fw.write ("\n\nGRUB_MOD_FINI(%s)\n" % modname)
            fw.write ("{\n")
            for ciphername in ciphernames:
                chmsg = "Unregister cipher %s" % ciphername
                chlognew = "%s\n	%s" % (chlognew, chmsg)
                fw.write ("  grub_cipher_unregister (&%s);\n" % ciphername)
            for mdname in mdnames:
                chmsg = "Unregister MD %s" % mdname
                chlognew = "%s\n	%s" % (chlognew, chmsg)
                fw.write ("  grub_md_unregister (&%s);\n" % mdname)
            for pkname in pknames:
                chmsg = "Unregister algorithm %s" % pkname
                chlognew = "%s\n	%s" % (chlognew, chmsg)
                fw.write ("  grub_pk_unregister (&%s);\n" % pkname)
            fw.write ("}\n")
            conf.write ("module = {\n")
            conf.write ("  name = %s;\n" % modname)
            for src in modfiles.split():
                conf.write ("  common = %s;\n" % src)
                confutil.write ("  common = grub-core/%s;\n" % src)
            if modname == "gcry_rijndael" or modname == "gcry_md4" or modname == "gcry_md5" or modname == "gcry_rmd160" or modname == "gcry_sha1" or modname == "gcry_sha256" or modname == "gcry_sha512" or modname == "gcry_tiger":
                # Alignment checked by hand
                conf.write ("  cflags = '$(CFLAGS_GCRY) -Wno-cast-align -Wno-strict-aliasing';\n");
            else:
                conf.write ("  cflags = '$(CFLAGS_GCRY)';\n");
            conf.write ("  cppflags = '$(CPPFLAGS_GCRY)';\n");
            conf.write ("};\n\n")
            f.close ()
            fw.close ()
            if nch:
                chlog = "%s%s\n" % (chlog, chlognew)
        elif isc and cipher_file != "camellia.c":
            print ("WARNING: C file isn't a module: %s" % cipher_file)
            f.close ()
            fw.close ()
            os.remove (outfile)
            chlog = "%s\n	* %s: Removed" % (chlog, cipher_file)
        continue
    chlog = "%s%sSkipped unknown file\n" % (chlog, chlognew)
    print ("WARNING: unknown file %s" % cipher_file)

cryptolist.close ()
chlog = "%s	* crypto.lst: New file.\n" % chlog

outfile = os.path.join (mpi_dir_out, "mpi.h")
fw=codecs.open (outfile, "w", "utf-8")
fw.write ("#include <grub/types.h>\n")
fw.write ("#include <cipher_wrap.h>\n")
chlog = "%s	* mpi.h: New file.\n" % chlog
fw.close ()

outfile = os.path.join (mpi_dir_out, "mpi-asm-defs.h")
fw=codecs.open (outfile, "w", "utf-8")
fw.write ("#include <grub/types.h>\n")
fw.write ("#include <cipher_wrap.h>\n")
chlog = "%s	* mpi-asm-defs.h: New file.\n" % chlog
fw.close ()

outfile = os.path.join (mpi_dir_out, "g10lib.h")
fw=codecs.open (outfile, "w", "utf-8")
fw.write ("#include <cipher_wrap.h>\n")
chlog = "%s	* g10lib.h: Likewise.\n" % chlog
fw.close ()

outfile = os.path.join (cipher_dir_out, "types.h")
fw=codecs.open (outfile, "w", "utf-8")
fw.write ("#include <grub/types.h>\n")
fw.write ("#include <cipher_wrap.h>\n")
chlog = "%s	* types.h: New file.\n" % chlog
fw.close ()

outfile = os.path.join (cipher_dir_out, "memory.h")
fw=codecs.open (outfile, "w", "utf-8")
fw.write ("#include <cipher_wrap.h>\n")
chlog = "%s	* memory.h: New file.\n" % chlog
fw.close ()


outfile = os.path.join (cipher_dir_out, "cipher.h")
fw=codecs.open (outfile, "w", "utf-8")
fw.write ("#include <grub/crypto.h>\n")
fw.write ("#include <cipher_wrap.h>\n")
chlog = "%s	* cipher.h: Likewise.\n" % chlog
fw.close ()

outfile = os.path.join (cipher_dir_out, "g10lib.h")
fw=codecs.open (outfile, "w", "utf-8")
fw.write ("#include <cipher_wrap.h>\n")
chlog = "%s	* g10lib.h: Likewise.\n" % chlog
fw.close ()

outfile = os.path.join (cipher_dir_out, "mpi.h")
fw=codecs.open (outfile, "w", "utf-8")
fw.write ("#include <cipher_wrap.h>\n")
chlog = "%s	* mpi.h: Likewise.\n" % chlog
fw.close ()

infile = os.path.join (cipher_dir_in, "ChangeLog")
outfile = os.path.join (cipher_dir_out, "ChangeLog")

conf.close ();

initfile = codecs.open (os.path.join (cipher_dir_out, "init.c"), "w", "utf-8")
initfile.write ("#include <grub/crypto.h>\n")
for module in modules:
    initfile.write ("extern void grub_%s_init (void);\n" % module)
    initfile.write ("extern void grub_%s_fini (void);\n" % module)
initfile.write ("\n")
initfile.write ("void\n")
initfile.write ("grub_gcry_init_all (void)\n")
initfile.write ("{\n")
for module in modules:
    initfile.write ("  grub_%s_init ();\n" % module)
initfile.write ("}\n")
initfile.write ("\n")
initfile.write ("void\n")
initfile.write ("grub_gcry_fini_all (void)\n")
initfile.write ("{\n")
for module in modules:
    initfile.write ("  grub_%s_fini ();\n" % module)
initfile.write ("}\n")
initfile.close ()

confutil.write ("  common = grub-core/lib/libgcrypt-grub/cipher/init.c;\n")
confutil.write ("};\n");
confutil.close ();


f=codecs.open (infile, "r", "utf-8")
fw=codecs.open (outfile, "w", "utf-8")
dt = datetime.date.today ()
fw.write ("%04d-%02d-%02d  Automatic import tool\n" % \
          (dt.year,dt.month, dt.day))
fw.write ("\n")
fw.write ("	Imported ciphers to GRUB\n")
fw.write ("\n")
fw.write (chlog)
fw.write ("\n")
for line in f:
    fw.write (line)
f.close ()
fw.close ()
