# -*- coding: utf-8 -*-

import pyaes


def prepare_text(password):
	if len(password) < 32:
		return "%s%s" % (password, "".join("0" for _ in range(32 - len(password))))
	else:
		return password[:32]


def _get_crypter(password):
	try:
		dc = pyaes.AESModeOfOperationCTR(password.encode(errors="ignore"))
	except TypeError:
		dc = pyaes.AESModeOfOperationCTR(password)

	return dc


def crypt(text, password):
	if not password:
		return text.encode(errors="ignore")

	try:
		return _get_crypter(password).encrypt(text)
	except (TypeError, AttributeError):
		return _get_crypter(password).encrypt(text.encode(errors="ignore"))


def decrypt(text, password):
	if not password:
		return text.decode(errors="ignore")

	try:
		return _get_crypter(password).decrypt(text).decode(errors="ignore")
	except (TypeError, AttributeError):
		return _get_crypter(password).decrypt(text.decode())

