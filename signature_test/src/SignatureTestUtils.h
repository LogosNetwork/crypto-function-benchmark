/*
 * SignatureTestUtils.h
 *
 *  Created on: Jun 18, 2018
 *      Author: peng
 */

#ifndef SIGNATURETESTUTILS_H_
#define SIGNATURETESTUTILS_H_
#include <string>
#include <iostream>
#include <vector>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

using namespace std;

namespace CryptoPerfTest
{
class SignatureTestUtils {
public:

static void getStrings(int size, int num_strings, vector<string> &strings)
{
	assert(size > 0 && num_strings > 0);

	strings.clear();
	strings.resize(num_strings);
	assert(strings.size() == (size_t)num_strings);

	for(auto &s : strings)
	{
		s.resize(size);
		assert(s.size() == (size_t)size);
		int pos = rand() % size;
		s[pos] = rand() % 256;
	}
//	cout << __func__ << " generated " << strings.size() << " strings with length " << strings[0].size() << endl;
}

static void getStrings(int size, int num_strings, vector<vector<unsigned char> > &strings)
{
	assert(size > 0 && num_strings > 0);

	strings.clear();
	strings.resize(num_strings);
	assert(strings.size() == (size_t)num_strings);

	for(auto &s : strings)
	{
		s.resize(size);
		assert(s.size() == (size_t)size);
		int pos = rand() % size;
		s[pos] = rand() % 256;
	}
//	cout << __func__ << " generated " << strings.size() << " strings with length " << strings[0].size() << endl;
}

static double ticks2ms(clock_t t, int rounds)
{
	return ((double)t)/CLOCKS_PER_SEC/rounds*1000;
}

};
}
#endif /* SIGNATURETESTUTILS_H_ */
