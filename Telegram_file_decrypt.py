# Script By Py0zz1

import hashlib
import binascii
import cryptg
import os,sys

o_Localkey_file = "LocalKey.dat"
o_AuthKey_file = "AuthKey.dat"


def load_dec_key(file):
	return file[0x00:0x10]


def generate_Localkey(LocalKey_Block,BaseKey):
	print("\n[+] ======= Generate LocalKey =======\n")

	Localkey_dec_key = load_dec_key(LocalKey_Block)
	print("[DEC_KEY] " + Localkey_dec_key.hex())
	print("")

	AES_KEY, AES_IV  = prepare_AES(Localkey_dec_key,BaseKey)
	enc_LocalKey = LocalKey_Block[0x10:]

	LocalKey = cryptg.decrypt_ige(enc_LocalKey,AES_KEY,AES_IV)

	print("[LOCALKEY]")
	print(LocalKey.hex())
	open(o_Localkey_file,"wb").write(LocalKey)


def prepare_AES(dec_key,BaseKey):

	x = 0x08

	cur = x
	data_a = dec_key
	data_a += BaseKey[cur:cur+0x20] # 48byte

	sha1_a = hashlib.sha1(data_a)

	cur += 0x20
	data_b = BaseKey[cur:cur+0x10]
	data_b += dec_key
	cur += 0x10
	data_b += BaseKey[cur:cur+0x10] #48byte

	sha1_b = hashlib.sha1(data_b)

	cur += 0x10
	data_c = BaseKey[cur:cur+0x20] #48byte
	data_c += dec_key

	sha1_c = hashlib.sha1(data_c)

	cur += 0x20
	data_d = dec_key
	data_d += BaseKey[cur:cur+0x20] #48byte

	sha1_d = hashlib.sha1(data_d)

	KEY = sha1_a.digest()[:0x08]
	KEY += sha1_b.digest()[0x08:0x14]
	KEY += sha1_c.digest()[0x04:0x10]


	IV = sha1_a.digest()[0x08:0x14]
	IV += sha1_b.digest()[:0x08]
	IV += sha1_c.digest()[0x10:0x14]
	IV += sha1_d.digest()[:0x08]

	print("[AES_KEY (32byte)] " + KEY.hex())
	print("[AES_IV  (32byte)] " + IV.hex())
	print("")

	return KEY,IV



def createBaseKey(salt):
	BaseKey = hashlib.pbkdf2_hmac('sha1',b'',salt, 4, 0x100)

	print("\n[+] ======= Create BaseKey =======\n")
	print("[Algorithm] PKCS5_PBKDF2_HMAC_SHA1 (256Byte)")

	print(BaseKey.hex())

	return BaseKey



def load_maps(path):
	with open(path,'rb') as f:
		maps = f.read()
		cur = 0x00


		print("\n[+] ======= maps Parse =======\n")
		header = maps[cur:cur+4]
		print("[HEADER] " + header.decode("utf-8"))
		print("")

		cur += 0x04
		version = maps[cur:cur+4]
		print("[VERSION] " + version.hex())
		print("")

		cur += 0x04
		salt_len = int.from_bytes(maps[cur:cur+4],'big')
		print("[SALT_LEN] " + hex(salt_len))
		print("")

		cur += 0x04
		salt = maps[cur:cur+salt_len]
		print("[SALT] " + salt.hex())
		print("")

		cur += salt_len
		LocalKey_Block_len = int.from_bytes(maps[cur:cur+4],'big')
		print("[LOCALKEY_BLOCK_LEN] " + hex(LocalKey_Block_len))
		print("")

		cur += 0x04
		LocalKey_Block = maps[cur:cur+LocalKey_Block_len]


		# load_maps() Result: BaseKey, Localkey_Block

		BaseKey = createBaseKey(salt)

		generate_Localkey(LocalKey_Block,BaseKey)


def generate_AuthKey(path):
	if os.path.exists(o_Localkey_file) and os.stat(o_Localkey_file).st_size :
		print("\n[+] ======= Generate AuthKey =======\n")
		LocalKey = open(o_Localkey_file,"rb").read()[0x04:]
		AuthKey_file = open(path,"rb").read()


		cur = 0x00
		header = AuthKey_file[cur:cur+4]
		print("[HEADER] " + header.decode("utf-8"))
		print("")

		cur += 0x04
		version = AuthKey_file[cur:cur+4]
		print("[VERSION] " + version.hex())
		print("")

		cur += 0x04
		AuthKey_Block_len = int.from_bytes(AuthKey_file[cur:cur+4],'big')
		print("[AUTHKEY_BLOCK_LEN] " + hex(AuthKey_Block_len))
		print("")

		cur += 0x04
		AuthKey_block = AuthKey_file[cur:cur+AuthKey_Block_len]

		AuthKey_dec_key = load_dec_key(AuthKey_block)
		print("[DEC_KEY] " + AuthKey_dec_key.hex())
		print("")

		AES_KEY, AES_IV  = prepare_AES(AuthKey_dec_key,LocalKey)

		enc_AuthKey = AuthKey_block[0x10:]

		AuthKey = cryptg.decrypt_ige(enc_AuthKey,AES_KEY,AES_IV)

		print("[AUTHKEY]")
		print(AuthKey.hex())
		open(o_AuthKey_file,"wb").write(AuthKey)

	else:
		print("[!] LOCALKEY NOT FOUND")


def usage():
	print("[TELEGRAM DECRYPT SCRIPT]\n\n")
	print("[Usage] {} [OPTION] [FILE_PATH]\n".format(sys.argv[0]))
	print("--init: Generate LocalKey (Require \'maps\' File)")
	print("--authkey: Decrypt Authkey File (Require \'D8~ ~ ~\' File)\n")

	print("Ex) {} --init C:\\Users\\py0zz1\\AppData\\Roaming\\Telegram Desktop\\tdata\\D877F783D5D3EF8Cs\\maps".format(sys.argv[0]))
	print("Ex) {} --authkey C:\\Users\\py0zz1\\AppData\\Roaming\\Telegram Desktop\\tdata\\D877F783D5D3EF8Cs".format(sys.argv[0]))
	print("\n------------------------------------------\n")


if __name__ == "__main__":
	if len(sys.argv) != 3:
		usage()

	else:
		if sys.argv[1] == "--init":
			load_maps(sys.argv[2])

		elif sys.argv[1] == "--authkey":
			generate_AuthKey(sys.argv[2])


