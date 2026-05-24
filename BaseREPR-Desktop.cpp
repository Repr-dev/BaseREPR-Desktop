
#include <iostream>
#include <string>
#include <windows.h>
#include <bcrypt.h>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <regex>
#include <cstring>
#include <vector>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

using namespace std;


// BaseREPR encryption/decryption utilities (updated--C++ edition)
string ogS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._+!'(%,$/:=*;)?<>@&^%|[]{} `#\\~\t\n";
string s;
const short BASE = 97;

long long strToIntBasic(string str) {
	unsigned long long result = 0;
	for (int i = 0; i < str.length(); i++) {
		int digit = ogS.find(str[i]);

		result *= 10;
		result += digit;
	}

	return result;
}

string sha256(const string& input) {
	// Handle for the hashing algorithm
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	// Handle for the hash object
	BCRYPT_HASH_HANDLE hHash = NULL;
	// The hash output
	DWORD dwHashObject = 0;
	DWORD dwData = 0;
	BYTE* pbHash = NULL;

	// Open the algorithm provider for SHA-256
	if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) {
		cerr << "Error: Failed to open SHA-256 algorithm provider." << endl;
		return "";
	}

	// Determine the size of the hash object
	if (BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&dwHashObject, sizeof(DWORD), &dwData, 0) != 0) {
		cerr << "Error: Failed to get hash object size." << endl;
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return "";
	}

	// Allocate memory for the hash object
	pbHash = new BYTE[dwHashObject];

	// Create a hash object
	if (BCryptCreateHash(hAlgorithm, &hHash, pbHash, dwHashObject, NULL, 0, 0) != 0) {
		cerr << "Error: Failed to create hash object." << endl;
		delete[] pbHash;
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return "";
	}

	// Hash the input string
	if (BCryptHashData(hHash, (PBYTE)input.c_str(), (ULONG)input.length(), 0) != 0) {
		cerr << "Error: Failed to hash data." << endl;
		delete[] pbHash;
		BCryptDestroyHash(hHash);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return "";
	}

	// Get the final hash value
	DWORD dwHashLength = 0;
	if (BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PBYTE)&dwHashLength, sizeof(DWORD), &dwData, 0) != 0) {
		cerr << "Error: Failed to get hash length." << endl;
		delete[] pbHash;
		BCryptDestroyHash(hHash);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return "";
	}

	// Allocate space for the hash value
	BYTE* pbResult = new BYTE[dwHashLength];

	// Finalize the hash computation
	if (BCryptFinishHash(hHash, pbResult, dwHashLength, 0) != 0) {
		cerr << "Error: Failed to finish hashing." << endl;
		delete[] pbHash;
		delete[] pbResult;
		BCryptDestroyHash(hHash);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return "";
	}

	// Convert the hash to a hexadecimal string
	stringstream hexStream;
	for (DWORD i = 0; i < dwHashLength; i++) {
		hexStream << hex << setw(2) << setfill('0') << (int)pbResult[i];
	}

	// Clean up
	delete[] pbHash;
	delete[] pbResult;
	BCryptDestroyHash(hHash);
	BCryptCloseAlgorithmProvider(hAlgorithm, 0);

	return hexStream.str(); // Return the hash as a string
}

long long keyToInt(string key) {
	string keySHA = sha256(key);

	unsigned long long count = 0;
	for (int i = 0; i < keySHA.length(); i++) {
		count += ogS.find(keySHA[i]) * pow(i, 21);
	}

	count = abs(strToIntBasic(key) - llround(log(count) * pow(count, 2)));

	unsigned short targetDigits = 16;
	unsigned short countLength = to_string(count).length();
	if (countLength < targetDigits) {
		unsigned short placeDiff = targetDigits - countLength;
		count *= (5 * targetDigits * placeDiff);
	}

	string countAsStr = to_string(count);
	if (key.length() % 2 == 0) {
		reverse(countAsStr.begin(), countAsStr.end());
	}

	regex rgx("/[\.e\+]/g");
	countAsStr = regex_replace(countAsStr, rgx, "");

	if (countAsStr.length() > 16) {
		countAsStr = countAsStr.substr(countAsStr.length() - 16);
	}

	return stoull(countAsStr);
}

void setupSWithKey(string keyText) {
	char startSArr[BASE];
	for (int i = 0; i < BASE; i++) {
		startSArr[i] = ogS[i];
	}

	unsigned long long k = keyToInt(keyText);

	for (int i = 0; i < BASE; i++) {
		short timesToShift = (i * k) % BASE;
		char elm = startSArr[i];

		for (int j = i; j < i + timesToShift; j++) {
			startSArr[j % BASE] = startSArr[(j + 1) % BASE];
		}
		startSArr[(i + timesToShift) % BASE] = elm;
	}
	for (int i = BASE - 1; i >= 0; i--) {
		short timesToShift = (i * k) % BASE;
		char elm = startSArr[i];

		for (int j = i; j < i + timesToShift; j++) {
			startSArr[j % BASE] = startSArr[(j + 1) % BASE];
		}
		startSArr[(i + timesToShift) % BASE] = elm;
	}

	if ((keyText.length() % 2) == 0) {
		reverse(begin(startSArr), end(startSArr));
	}

	s = startSArr;
}


// C++-specific code
static const string base64Chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

string btoa(const string& in) {
	string out;
	int val = 0;
	int valb = -6;

	for (unsigned char c : in) {
		val = (val << 8) + c;
		valb += 8;
		while (valb >= 0) {
			out.push_back(base64Chars[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}

	if (valb > -6) out.push_back(base64Chars[((val << 8) >> valb) & 0x3F]);
	while (out.size() % 4) out.push_back('=');
	return out;
}

string atob(const string& in) {
	vector<int> T(256, -1);
	for (int i = 0; i < 64; i++) T[base64Chars[i]] = i;

	string out;
	int val = 0;
	int valb = -8;

	for (unsigned char c : in) {
		if (T[c] == -1) break;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0) {
			out.push_back(char((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
}


// Execution functions
string plaintextToCiphertext(string plaintxt) {
	reverse(plaintxt.begin(), plaintxt.end());

	vector<char> newArr(plaintxt.begin(), plaintxt.end());

	for (size_t i = 0; i < plaintxt.length(); i++) {
		newArr[i] = s[ogS.find(plaintxt[i])];
	}

	// Convert to string
	string newArrAsStr(newArr.begin(), newArr.end());
	return btoa(newArrAsStr);
}

string ciphertextToPlaintext(string ciphertxt) {
	ciphertxt = atob(ciphertxt);
	vector<char> ctArr(ciphertxt.begin(), ciphertxt.end());

	for (size_t i = 0; i < ciphertxt.length(); i++) {
		ctArr[i] = ogS[s.find(ctArr[i])];
	}
	reverse(ciphertxt.begin(), ciphertxt.end());

	// Convert to string
	string ctArrAsStr(ctArr.begin(), ctArr.end());
	reverse(ctArrAsStr.begin(), ctArrAsStr.end());

	return ctArrAsStr;
}


// For C++ edition
int checkInputForSpecialCmds(string in) {
	if (in == "!cmd-exit") {
		return 0;
	}
	else if (in == "!cmd-res") {
		return 42;
	}
	
	return -165;
}

void logStartupText() {
	cout << " ____                 _____  ______ _____  _____\n|  _ \\               |  __ \\|  ____|  __ \\|  __ \\\n| |_) | __ _ ___  ___| |__) | |__  | |__) | |__) |\n|  _ < / _` / __|/ _ \\  _  /|  __| |  ___/|  _  /\n| |_) | (_| \\__ \\  __/ | \\ \\| |____| |    | | \\ \\\n|____/ \\__,_|___/\\___|_|  \\_\\______|_|    |_|  \\_\\";
	cout << "\nBaseREPR v1.0.3\nC++ Edition v1.0.0\n\n\nThe C++ edition of BaseREPR uses an updated algorithm and supports the following special commands:\n\n!cmd-res      Starts a new session and clears all previous ones\n!cmd-exit     Closes the application\n\n\n";
}

void logNewSessionText() {
	cout << "\n";
	cout << "- NEW SESSION -\n\n";
}

string getUserInput() {
	string userInput;
	
	getline(cin, userInput);

	return userInput;
}


// Main program
int main()
{
	logStartupText();

	while (true) {
		cout << "Would you like to ENCODE (type \"e\") or DECODE (type \"d\")? > ";
		string eOrD = getUserInput();

		if (eOrD == "e") {
			cout << "Text to encode? > ";
			string plaintext = getUserInput();

			if (checkInputForSpecialCmds(plaintext) == 0)
				return 0;
			else if (checkInputForSpecialCmds(plaintext) == 42) {
				system("cls");
				logStartupText();
				logNewSessionText();
				continue;
			}

			cout << "Encryption key? (only you and the recipient should know this) > ";
			string key = getUserInput();

			if (checkInputForSpecialCmds(key) == 0)
				return 0;
			else if (checkInputForSpecialCmds(key) == 42) {
				system("cls");
				logStartupText();
				logNewSessionText();
				continue;
			}

			setupSWithKey(key);
			string ciphertext = plaintextToCiphertext(plaintext);

			cout << "\n----- ENCRYPTION RESULT -----\n\nCiphertext: " << ciphertext << "\nPlaintext: " << plaintext << "\nKey: " << key << "\n";
		}
		else if (eOrD == "d") {

			cout << "Text to decode? (take care to get everything correct) > ";
			string ciphertext = getUserInput();

			if (checkInputForSpecialCmds(ciphertext) == 0)
				return 0;
			else if (checkInputForSpecialCmds(ciphertext) == 42) {
				system("cls");
				logStartupText();
				logNewSessionText();
				continue;
			}

			cout << "Decryption key? > ";
			string key = getUserInput();

			if (checkInputForSpecialCmds(key) == 0)
				return 0;
			else if (checkInputForSpecialCmds(key) == 42) {
				system("cls");
				logStartupText();
				logNewSessionText();
				continue;
			}


			setupSWithKey(key);
			string plaintext = ciphertextToPlaintext(ciphertext);

			cout << "\n----- DECRYPTION RESULT -----\n\nPlaintext: " << plaintext << "\nCiphertext: " << ciphertext << "\nKey Used: " << key << "\n";
		}
		else {
			if (checkInputForSpecialCmds(eOrD) == 0)
				return 0;
			else if (checkInputForSpecialCmds(eOrD) == 42) {
				system("cls");
				logStartupText();
				logNewSessionText();
				continue;
			}

			cout << "Invalid response. Must type \"e\" or \"d\".\n";
		}

		logNewSessionText();
	}
}
