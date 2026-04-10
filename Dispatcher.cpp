#include "Dispatcher.hpp"

// Includes
#include <stdexcept>
#include <iostream>
#include <thread>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <cstring>

#if defined(__APPLE__) || defined(__MACOSX)
#include <machine/endian.h>
#else
#include <arpa/inet.h>
#endif

#include "precomp.hpp"

#ifndef htonll
#define htonll(x) ((((uint64_t)htonl(x)) << 32) | htonl((x) >> 32))
#endif

static std::string::size_type fromHex(char c) {
	if (c >= 'A' && c <= 'F') {
		c += 'a' - 'A';
	}

	const std::string hex = "0123456789abcdef";
	const std::string::size_type ret = hex.find(c);
	return ret;
}

static cl_ulong4 fromHex(const std::string & strHex) {
	uint8_t data[32];
	std::fill(data, data + sizeof(data), cl_uchar(0));

	auto index = 0;
	for(size_t i = 0; i < strHex.size(); i += 2) {
		const auto indexHi = fromHex(strHex[i]);
		const auto indexLo = i + 1 < strHex.size() ? fromHex(strHex[i+1]) : std::string::npos;

		const auto valHi = (indexHi == std::string::npos) ? 0 : indexHi << 4;
		const auto valLo = (indexLo == std::string::npos) ? 0 : indexLo;

		data[index] = valHi | valLo;
		++index;
	}

	cl_ulong4 res = {
		.s = {
			htonll(*(uint64_t *)(data + 24)),
			htonll(*(uint64_t *)(data + 16)),
			htonll(*(uint64_t *)(data + 8)),
			htonll(*(uint64_t *)(data + 0)),
		}
	};
	return res;
}

static std::string toHex(const uint8_t * const s, const size_t len) {
	std::string b("0123456789abcdef");
	std::string r;

	for (size_t i = 0; i < len; ++i) {
		const unsigned char h = s[i] / 16;
		const unsigned char l = s[i] % 16;

		r = r + b.substr(h, 1) + b.substr(l, 1);
	}

	return r;
}

static std::string formatPrivateKey(cl_ulong4 seed, cl_ulong round, cl_uint foundId) {
	cl_ulong carry = 0;
	cl_ulong4 seedRes;

	seedRes.s[0] = seed.s[0] + round; carry = seedRes.s[0] < round;
	seedRes.s[1] = seed.s[1] + carry; carry = !seedRes.s[1];
	seedRes.s[2] = seed.s[2] + carry; carry = !seedRes.s[2];
	seedRes.s[3] = seed.s[3] + carry + foundId;

	std::ostringstream ss;
	ss << std::hex << std::setfill('0');
	ss << std::setw(16) << seedRes.s[3] << std::setw(16) << seedRes.s[2] << std::setw(16) << seedRes.s[1] << std::setw(16) << seedRes.s[0];

	return ss.str();
}

static void printResult(cl_ulong4 seed, cl_ulong round, result r, cl_uchar score, const std::chrono::time_point<std::chrono::steady_clock> & timeStart, const Mode & mode) {
	// Time delta
	const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - timeStart).count();

	// Format private key
	const std::string strPrivate = formatPrivateKey(seed, round, r.foundId);

	// Format public key
	const std::string strPublic = toHex(r.foundHash, 20);

	// Print
	const std::string strVT100ClearLine = "\33[2K\r";
	std::cout << strVT100ClearLine << "  Time: " << std::setw(5) << seconds << "s";

	if (!mode.isMatchAll) {
		std::cout << " Score: " << std::setw(2) << (int) score;
	}

	std::cout << " Private: 0x" << strPrivate << ' ';
	std::cout << mode.transformName();
	std::cout << ": 0x" << strPublic << std::endl;
}

// Keccak-256 for EIP-55 checksum postprocessing

static const uint64_t keccakRC[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakRho[24] = { 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44 };
static const int keccakPi[24]  = { 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1 };

static uint64_t rotl64(uint64_t x, int n) {
	return (x << n) | (x >> (64 - n));
}

static void keccakF1600(uint64_t st[25]) {
	for (uint64_t round : keccakRC) {
		uint64_t C[5], D[5];
		for (int x = 0; x < 5; ++x) C[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20];
		for (int x = 0; x < 5; ++x) D[x] = C[(x+4)%5] ^ rotl64(C[(x+1)%5], 1);
		for (int i = 0; i < 25; ++i) st[i] ^= D[i%5];

		uint64_t tmp = st[1];
		for (int i = 0; i < 24; ++i) {
			int j = keccakPi[i];
			uint64_t t = st[j];
			st[j] = rotl64(tmp, keccakRho[i]);
			tmp = t;
		}

		for (int y = 0; y < 25; y += 5) {
			uint64_t t[5];
			for (int x = 0; x < 5; ++x) t[x] = st[y+x];
			for (int x = 0; x < 5; ++x) st[y+x] = t[x] ^ (~t[(x+1)%5] & t[(x+2)%5]);
		}

		st[0] ^= round;
	}
}

static void keccak256(const uint8_t * input, size_t len, uint8_t output[32]) {
	uint64_t st[25] = {0};
	const size_t rate = 136;
	size_t offset = 0;

	while (len - offset >= rate) {
		for (size_t i = 0; i < rate / 8; ++i) {
			uint64_t t = 0;
			memcpy(&t, input + offset + i * 8, 8);
			st[i] ^= t;
		}
		keccakF1600(st);
		offset += rate;
	}

	uint8_t temp[136] = {0};
	memcpy(temp, input + offset, len - offset);
	temp[len - offset] = 0x01;
	temp[rate - 1] ^= 0x80;

	for (size_t i = 0; i < rate / 8; ++i) {
		uint64_t t = 0;
		memcpy(&t, temp + i * 8, 8);
		st[i] ^= t;
	}
	keccakF1600(st);

	memcpy(output, st, 32);
}

static std::string eip55Checksum(const uint8_t addr20[20]) {
	const std::string lower = toHex(addr20, 20);
	uint8_t hashBytes[32];
	keccak256(reinterpret_cast<const uint8_t *>(lower.data()), lower.size(), hashBytes);

	std::string result = lower;
	for (size_t i = 0; i < 40; ++i) {
		if (result[i] >= 'a' && result[i] <= 'f') {
			const uint8_t nibble = (i % 2 == 0) ? (hashBytes[i / 2] >> 4) : (hashBytes[i / 2] & 0x0F);
			if (nibble >= 8) {
				result[i] = static_cast<char>(result[i] - 'a' + 'A');
			}
		}
	}
	return result;
}

static bool checksumMatches(const std::string & checksummedAddress, const std::string & rawPattern) {
	for (size_t i = 0; i < rawPattern.size() && i < checksummedAddress.size(); ++i) {
		const char c = rawPattern[i];
		if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			if (checksummedAddress[i] != c) {
				return false;
			}
		}
	}
	return true;
}

unsigned int getKernelExecutionTimeMicros(cl_event & e) {
	cl_ulong timeStart = 0, timeEnd = 0;
	clWaitForEvents(1, &e);
	clGetEventProfilingInfo(e, CL_PROFILING_COMMAND_START, sizeof(timeStart), &timeStart, NULL);
	clGetEventProfilingInfo(e, CL_PROFILING_COMMAND_END, sizeof(timeEnd), &timeEnd, NULL);
	return (timeEnd - timeStart) / 1000;
}

Dispatcher::OpenCLException::OpenCLException(const std::string s, const cl_int res) :
	std::runtime_error( s + " (res = " + toString(res) + ")"),
	m_res(res)
{

}

void Dispatcher::OpenCLException::OpenCLException::throwIfError(const std::string s, const cl_int res) {
	if (res != CL_SUCCESS) {
		throw OpenCLException(s, res);
	}
}

cl_command_queue Dispatcher::Device::createQueue(cl_context & clContext, cl_device_id & clDeviceId) {
	// nVidia CUDA Toolkit 10.1 only supports OpenCL 1.2 so we revert back to older functions for compatability
#ifdef PROFANITY_DEBUG
	cl_command_queue_properties p = CL_QUEUE_PROFILING_ENABLE;
#else
	cl_command_queue_properties p = NULL;
#endif

#ifdef CL_VERSION_2_0
	const cl_command_queue ret = clCreateCommandQueueWithProperties(clContext, clDeviceId, &p, NULL);
#else
	const cl_command_queue ret = clCreateCommandQueue(clContext, clDeviceId, p, NULL);
#endif
	return ret == NULL ? throw std::runtime_error("failed to create command queue") : ret;
}

cl_kernel Dispatcher::Device::createKernel(cl_program & clProgram, const std::string s) {
	cl_kernel ret  = clCreateKernel(clProgram, s.c_str(), NULL);
	return ret == NULL ? throw std::runtime_error("failed to create kernel \"" + s + "\"") : ret;
}

cl_ulong4 Dispatcher::Device::createSeed() {
#ifdef PROFANITY_DEBUG
	cl_ulong4 r;
	r.s[0] = 1;
	r.s[1] = 1;
	r.s[2] = 1;
	r.s[3] = 1;
	return r;
#else
	// We do not need really safe crypto random here, since we inherit safety
	// of the key from the user-provided seed public key.
	// We only need this random to not repeat same job among different devices
	std::random_device rd;

	cl_ulong4 diff;
	diff.s[0] = (((uint64_t)rd()) << 32) | rd();
	diff.s[1] = (((uint64_t)rd()) << 32) | rd();
	diff.s[2] = (((uint64_t)rd()) << 32) | rd();
	diff.s[3] = (((uint64_t)rd() & 0x0000ffff) << 32) | rd(); // zeroing 2 highest bytes to prevent overflowing sum private key after adding to seed private key
	return diff;
#endif
}

Dispatcher::Device::Device(Dispatcher & parent, cl_context & clContext, cl_program & clProgram, cl_device_id clDeviceId, const size_t worksizeLocal, const size_t size, const size_t index, const Mode & mode, cl_ulong4 clSeedX, cl_ulong4 clSeedY) :
	m_parent(parent),
	m_index(index),
	m_clDeviceId(clDeviceId),
	m_worksizeLocal(worksizeLocal),
	m_clScoreMax(0),
	m_clQueue(createQueue(clContext, clDeviceId) ),
	m_kernelInit( createKernel(clProgram, "profanity_init") ),
	m_kernelInverse(createKernel(clProgram, "profanity_inverse")),
	m_kernelIterate(createKernel(clProgram, "profanity_iterate")),
	m_kernelTransform( mode.transformKernel() == "" ? NULL : createKernel(clProgram, mode.transformKernel())),
	m_kernelScore(createKernel(clProgram, mode.kernel)),
	m_memPrecomp(clContext, m_clQueue, CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY, sizeof(g_precomp), g_precomp),
	m_memPointsDeltaX(clContext, m_clQueue, CL_MEM_READ_WRITE | CL_MEM_HOST_NO_ACCESS, size, true),
	m_memInversedNegativeDoubleGy(clContext, m_clQueue, CL_MEM_READ_WRITE | CL_MEM_HOST_NO_ACCESS, size, true),
	m_memPrevLambda(clContext, m_clQueue, CL_MEM_READ_WRITE | CL_MEM_HOST_NO_ACCESS, size, true),
	m_memResult(clContext, m_clQueue, CL_MEM_READ_WRITE | CL_MEM_HOST_READ_ONLY, mode.isMatchAll ? PROFANITY_MAX_RESULTS + 1 : PROFANITY_MAX_SCORE + 1),
	m_memData1(clContext, m_clQueue, CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY, 20),
	m_memData2(clContext, m_clQueue, CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY, 20),
	m_clSeed(createSeed()),
	m_clSeedX(clSeedX),
	m_clSeedY(clSeedY),
	m_round(0),
	m_speed(PROFANITY_SPEEDSAMPLES),
	m_sizeInitialized(0),
	m_eventFinished(NULL),
	m_lastTotalWritten(0)
{

}

Dispatcher::Device::~Device() {

}

Dispatcher::Dispatcher(cl_context & clContext, cl_program & clProgram, const Mode mode, const size_t worksizeMax, const size_t inverseSize, const size_t inverseMultiple, const cl_uint clScoreQuit, const std::string & seedPublicKey, const bool checksumMode, const size_t checksumTarget, const std::string & rawPattern, const size_t checksumCount)
	: m_clContext(clContext)
	, m_clProgram(clProgram)
	, m_mode(mode)
	, m_worksizeMax(worksizeMax)
	, m_inverseSize(inverseSize)
	, m_size(inverseSize*inverseMultiple)
	, m_clScoreMax(mode.score)
	, m_clScoreQuit(clScoreQuit)
	, m_eventFinished(NULL)
	, m_countPrint(0)
	, m_publicKeyX(fromHex(seedPublicKey.substr(0, 64)))
	, m_publicKeyY(fromHex(seedPublicKey.substr(64, 64)))
	, m_matchAllFound(0)
	, m_checksumMode(checksumMode)
	, m_checksumTarget(checksumTarget)
	, m_checksumCount(checksumCount)
	, m_rawPattern(rawPattern)
{
	if (m_checksumMode && m_checksumTarget > 0) {
		m_collectedResults.reserve(m_checksumTarget);
	}
}

Dispatcher::~Dispatcher() {

}

void Dispatcher::addDevice(cl_device_id clDeviceId, const size_t worksizeLocal, const size_t index) {
	Device * pDevice = new Device(*this, m_clContext, m_clProgram, clDeviceId, worksizeLocal, m_size, index, m_mode, m_publicKeyX, m_publicKeyY);
	m_vDevices.push_back(pDevice);
}

void Dispatcher::run() {
	m_eventFinished = clCreateUserEvent(m_clContext, NULL);
	timeStart = std::chrono::steady_clock::now();

	init();

	const auto timeInitialization = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - timeStart).count();
	std::cout << "Initialization time: " << timeInitialization << " seconds" << std::endl;

	if (m_mode.isMatchAll) {
		auto mask    = toHex(m_mode.data1, 20);
		auto pattern = toHex(m_mode.data2, 20);

		for (size_t i = 0; i < mask.size(); ++i) {
			if (mask[i] == '0') {
				pattern[i] = '_';
			}
		}

		std::cout << "Pattern: " << pattern << std::endl;
		std::cout << std::endl;
	}

	m_quit = false;
	m_countRunning = m_vDevices.size();

	std::cout << "Running..." << std::endl;
	std::cout << "  Always verify that a private key generated by this program corresponds to the" << std::endl;
	std::cout << "  public key printed by importing it to a wallet of your choice. This program" << std::endl;
	std::cout << "  like any software might contain bugs and it does by design cut corners to" << std::endl;
	std::cout << "  improve overall performance." << std::endl;
	std::cout << std::endl;

	for (auto it = m_vDevices.begin(); it != m_vDevices.end(); ++it) {
		dispatch(*(*it));
	}

	clWaitForEvents(1, &m_eventFinished);
	clReleaseEvent(m_eventFinished);
	m_eventFinished = NULL;
}

void Dispatcher::init() {
	std::cout << "Initializing devices..." << std::endl;
	std::cout << "  This should take less than a minute. The number of objects initialized on each" << std::endl;
	std::cout << "  device is equal to inverse-size * inverse-multiple. To lower" << std::endl;
	std::cout << "  initialization time (and memory footprint) I suggest lowering the" << std::endl;
	std::cout << "  inverse-multiple first. You can do this via the -I switch. Do note that" << std::endl;
	std::cout << "  this might negatively impact your performance." << std::endl;
	std::cout << std::endl;

	const auto deviceCount = m_vDevices.size();
	m_sizeInitTotal = m_size * deviceCount;
	m_sizeInitDone = 0;

	cl_event * const pInitEvents = new cl_event[deviceCount];

	for (size_t i = 0; i < deviceCount; ++i) {
		pInitEvents[i] = clCreateUserEvent(m_clContext, NULL);
		m_vDevices[i]->m_eventFinished = pInitEvents[i];
		initBegin(*m_vDevices[i]);
	}

	clWaitForEvents(deviceCount, pInitEvents);
	for (size_t i = 0; i < deviceCount; ++i) {
		m_vDevices[i]->m_eventFinished = NULL;
		clReleaseEvent(pInitEvents[i]);
	}

	delete[] pInitEvents;

	std::cout << std::endl;
}

void Dispatcher::initBegin(Device & d) {
	// Set mode data
	for (auto i = 0; i < 20; ++i) {
		d.m_memData1[i] = m_mode.data1[i];
		d.m_memData2[i] = m_mode.data2[i];
	}

	// Write precompute table and mode data
	d.m_memPrecomp.write(true);
	d.m_memData1.write(true);
	d.m_memData2.write(true);

	// Kernel arguments - profanity_begin
	d.m_memPrecomp.setKernelArg(d.m_kernelInit, 0);
	d.m_memPointsDeltaX.setKernelArg(d.m_kernelInit, 1);
	d.m_memPrevLambda.setKernelArg(d.m_kernelInit, 2);
	d.m_memResult.setKernelArg(d.m_kernelInit, 3);
	CLMemory<cl_ulong4>::setKernelArg(d.m_kernelInit, 4, d.m_clSeed);
	CLMemory<cl_ulong4>::setKernelArg(d.m_kernelInit, 5, d.m_clSeedX);
	CLMemory<cl_ulong4>::setKernelArg(d.m_kernelInit, 6, d.m_clSeedY);

	// Kernel arguments - profanity_inverse
	d.m_memPointsDeltaX.setKernelArg(d.m_kernelInverse, 0);
	d.m_memInversedNegativeDoubleGy.setKernelArg(d.m_kernelInverse, 1);

	// Kernel arguments - profanity_iterate
	d.m_memPointsDeltaX.setKernelArg(d.m_kernelIterate, 0);
	d.m_memInversedNegativeDoubleGy.setKernelArg(d.m_kernelIterate, 1);
	d.m_memPrevLambda.setKernelArg(d.m_kernelIterate, 2);

	// Kernel arguments - profanity_transform_*
	if(d.m_kernelTransform) {
		d.m_memInversedNegativeDoubleGy.setKernelArg(d.m_kernelTransform, 0);
	}

	// Kernel arguments - profanity_score_*
	d.m_memInversedNegativeDoubleGy.setKernelArg(d.m_kernelScore, 0);
	d.m_memResult.setKernelArg(d.m_kernelScore, 1);
	d.m_memData1.setKernelArg(d.m_kernelScore, 2);
	d.m_memData2.setKernelArg(d.m_kernelScore, 3);

	CLMemory<cl_uchar>::setKernelArg(d.m_kernelScore, 4, d.m_clScoreMax); // Updated in handleResult()

	// Seed device
	initContinue(d);
}

void Dispatcher::initContinue(Device & d) {
	size_t sizeLeft = m_size - d.m_sizeInitialized;
	const size_t sizeInitLimit = m_size / 20;

	// Print progress
	const size_t percentDone = m_sizeInitDone * 100 / m_sizeInitTotal;
	std::cout << "  " << percentDone << "%\r" << std::flush;

	if (sizeLeft) {
		cl_event event;
		const size_t sizeRun = std::min(sizeInitLimit, std::min(sizeLeft, m_worksizeMax));
		const auto resEnqueue = clEnqueueNDRangeKernel(d.m_clQueue, d.m_kernelInit, 1, &d.m_sizeInitialized, &sizeRun, NULL, 0, NULL, &event);
		OpenCLException::throwIfError("kernel queueing failed during initilization", resEnqueue);

		// See: https://www.khronos.org/registry/OpenCL/sdk/1.2/docs/man/xhtml/clSetEventCallback.html
		// If an application needs to wait for completion of a routine from the above list in a callback, please use the non-blocking form of the function, and
		// assign a completion callback to it to do the remainder of your work. Note that when a callback (or other code) enqueues commands to a command-queue,
		// the commands are not required to begin execution until the queue is flushed. In standard usage, blocking enqueue calls serve this role by implicitly
		// flushing the queue. Since blocking calls are not permitted in callbacks, those callbacks that enqueue commands on a command queue should either call
		// clFlush on the queue before returning or arrange for clFlush to be called later on another thread.
		clFlush(d.m_clQueue); 

		std::lock_guard<std::mutex> lock(m_mutex);
		d.m_sizeInitialized += sizeRun;
		m_sizeInitDone += sizeRun;

		const auto resCallback = clSetEventCallback(event, CL_COMPLETE, staticCallback, &d);
		OpenCLException::throwIfError("failed to set custom callback during initialization", resCallback);
	} else {
		// Printing one whole string at once helps in avoiding garbled output when executed in parallell
		const std::string strOutput = "  GPU" + toString(d.m_index) + " initialized";
		std::cout << strOutput << std::endl;
		clSetUserEventStatus(d.m_eventFinished, CL_COMPLETE);
	}
}

void Dispatcher::enqueueKernel(cl_command_queue & clQueue, cl_kernel & clKernel, size_t worksizeGlobal, const size_t worksizeLocal, cl_event * pEvent = NULL) {
	const size_t worksizeMax = m_worksizeMax;
	size_t worksizeOffset = 0;
	while (worksizeGlobal) {
		const size_t worksizeRun = std::min(worksizeGlobal, worksizeMax);
		const size_t * const pWorksizeLocal = (worksizeLocal == 0 ? NULL : &worksizeLocal);
		const auto res = clEnqueueNDRangeKernel(clQueue, clKernel, 1, &worksizeOffset, &worksizeRun, pWorksizeLocal, 0, NULL, pEvent);
		OpenCLException::throwIfError("kernel queueing failed", res);

		worksizeGlobal -= worksizeRun;
		worksizeOffset += worksizeRun;
	}
}

void Dispatcher::enqueueKernelDevice(Device & d, cl_kernel & clKernel, size_t worksizeGlobal, cl_event * pEvent = NULL) {
	try {
		enqueueKernel(d.m_clQueue, clKernel, worksizeGlobal, d.m_worksizeLocal, pEvent);
	} catch ( OpenCLException & e ) {
		// If local work size is invalid, abandon it and let implementation decide
		if ((e.m_res == CL_INVALID_WORK_GROUP_SIZE || e.m_res == CL_INVALID_WORK_ITEM_SIZE) && d.m_worksizeLocal != 0) {
			std::cout << std::endl << "warning: local work size abandoned on GPU" << d.m_index << std::endl;
			d.m_worksizeLocal = 0;
			enqueueKernel(d.m_clQueue, clKernel, worksizeGlobal, d.m_worksizeLocal, pEvent);
		}
		else {
			throw;
		}
	}
}

void Dispatcher::dispatch(Device & d) {
	cl_event event;
	d.m_memResult.read(false, &event);

#ifdef PROFANITY_DEBUG
	cl_event eventInverse;
	cl_event eventIterate;

	enqueueKernelDevice(d, d.m_kernelInverse, m_size / m_inverseSize, &eventInverse);
	enqueueKernelDevice(d, d.m_kernelIterate, m_size, &eventIterate);
#else
	enqueueKernelDevice(d, d.m_kernelInverse, m_size / m_inverseSize);
	enqueueKernelDevice(d, d.m_kernelIterate, m_size);
#endif

	if (d.m_kernelTransform) {
		enqueueKernelDevice(d, d.m_kernelTransform, m_size);
	}

	enqueueKernelDevice(d, d.m_kernelScore, m_size);
	clFlush(d.m_clQueue);

#ifdef PROFANITY_DEBUG
	// We're actually not allowed to call clFinish here because this function is ultimately asynchronously called by OpenCL.
	// However, this happens to work on my computer and it's not really intended for release, just something to aid me in
	// optimizations.
	clFinish(d.m_clQueue); 
	std::cout << "Timing: profanity_inverse = " << getKernelExecutionTimeMicros(eventInverse) << "us, profanity_iterate = " << getKernelExecutionTimeMicros(eventIterate) << "us" << std::endl;
#endif

	const auto res = clSetEventCallback(event, CL_COMPLETE, staticCallback, &d);
	OpenCLException::throwIfError("failed to set custom callback", res);
}

void Dispatcher::drainResults(Device & d) {
	const cl_uint totalWritten = d.m_memResult[0].found;
	const cl_uint newCount = totalWritten - d.m_lastTotalWritten;

	if (newCount == 0) {
		return;
	}

	if (newCount > PROFANITY_MAX_RESULTS) {
		std::cerr << std::endl << "warning: match-all buffer overflow, " << (newCount - PROFANITY_MAX_RESULTS) << " result(s) lost. Use a more specific pattern to avoid this." << std::endl;
	}

	const cl_uint toRead = std::min(newCount, (cl_uint) PROFANITY_MAX_RESULTS);
	const cl_uint startWritePos = totalWritten - toRead;

	if (m_checksumMode) {
		{
			std::lock_guard<std::mutex> lock(m_mutex);

			const size_t alreadyHave = m_collectedResults.size();
			if (alreadyHave < m_checksumTarget) {
				const size_t canAppend = m_checksumTarget - alreadyHave;
				const cl_uint toAppend = static_cast<cl_uint>(std::min(static_cast<size_t>(toRead), canAppend));
				const cl_long elapsed = static_cast<cl_long>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - timeStart).count());

				for (cl_uint i = 0; i < toAppend; ++i) {
					const cl_uint slot = ((startWritePos + i) % PROFANITY_MAX_RESULTS) + 1;
					CollectedResult cr{};
					cr.r = d.m_memResult[static_cast<int>(slot)];
					cr.seed = d.m_clSeed;
					cr.round = d.m_round;
					cr.foundSeconds = elapsed;
					m_collectedResults.push_back(cr);
				}

				if (m_collectedResults.size() >= m_checksumTarget) {
					m_quit = true;
				}
			}
		}

		d.m_lastTotalWritten = totalWritten;
	} else {
		{
			std::lock_guard<std::mutex> lock(m_mutex);

			for (cl_uint i = 0; i < toRead; ++i) {
				const cl_uint slot = ((startWritePos + i) % PROFANITY_MAX_RESULTS) + 1;
				printResult(d.m_clSeed, d.m_round, d.m_memResult[static_cast<int>(slot)], 0, timeStart, m_mode);
			}

			m_matchAllFound += newCount;
			if (m_clScoreQuit && m_matchAllFound >= m_clScoreQuit) {
				m_quit = true;
			}
		}

		d.m_lastTotalWritten = totalWritten;
	}
}

void Dispatcher::handleResult(Device & d) {
	if (m_mode.isMatchAll) {
		drainResults(d);
		return;
	}

	for (auto i = PROFANITY_MAX_SCORE; i > m_clScoreMax; --i) {
		result & r = d.m_memResult[i];

		if (r.found > 0 && i >= d.m_clScoreMax) {
			d.m_clScoreMax = i;
			CLMemory<cl_uchar>::setKernelArg(d.m_kernelScore, 4, d.m_clScoreMax);

			std::lock_guard<std::mutex> lock(m_mutex);
			if (i >= m_clScoreMax) {
				m_clScoreMax = i;

				if (m_clScoreQuit && (cl_uint)i >= m_clScoreQuit) {
					m_quit = true;
				}

				printResult(d.m_clSeed, d.m_round, r, i, timeStart, m_mode);
			}

			break;
		}
	}
}

void Dispatcher::onEvent(cl_event event, cl_int status, Device & d) {
	if (status != CL_COMPLETE) {
		std::cout << "Dispatcher::onEvent - Got bad status: " << status << std::endl;
	}
	else if (d.m_eventFinished != NULL) {
		initContinue(d);
	} else {
		++d.m_round;
		handleResult(d);

		bool bDispatch = true;
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			d.m_speed.sample(m_size);
			printSpeed();

			if( m_quit ) {
				bDispatch = false;
				if(--m_countRunning == 0) {
					clSetUserEventStatus(m_eventFinished, CL_COMPLETE);
				}
			}
		}

		if (bDispatch) {
			dispatch(d);
		}
	}
}

// This is run when m_mutex is held.
void Dispatcher::printSpeed() {
	++m_countPrint;
	if( m_countPrint > m_vDevices.size() ) {
		std::string strGPUs;
		double speedTotal = 0;
		unsigned int i = 0;
		for (auto & e : m_vDevices) {
			const auto curSpeed = e->m_speed.getSpeed();
			speedTotal += curSpeed;
			strGPUs += " GPU" + toString(e->m_index) + ": " + formatSpeed(curSpeed);
			++i;
		}

		const std::string strVT100ClearLine = "\33[2K\r";
		std::cerr << strVT100ClearLine << "Total: " << formatSpeed(speedTotal) << " -" << strGPUs;
		if(m_checksumMode) {
			std::cerr << " | Collected: " << m_collectedResults.size() << "/" << m_checksumTarget;
		}
		std::cerr << '\r' << std::flush;
		m_countPrint = 0;
	}
}

void Dispatcher::printChecksumResults() {
	if (!m_checksumMode) {
		return;
	}

	size_t found = 0;

	for (const auto & cr : m_collectedResults) {
		const std::string checksummed = eip55Checksum(cr.r.foundHash);

		if (!checksumMatches(checksummed, m_rawPattern)) {
			continue;
		}

		const std::string strPrivate = formatPrivateKey(cr.seed, cr.round, cr.r.foundId);

		const std::string strVT100ClearLine = "\33[2K\r";
		std::cout << strVT100ClearLine << "  Time: " << std::setw(5) << cr.foundSeconds << "s Private: 0x" << strPrivate << ' ' << m_mode.transformName() << ": 0x" << checksummed << std::endl;

		++found;
	}

	std::cout << "Found " << found << " of " << m_checksumCount << " addresses with matching checksum" << std::endl;
}

void CL_CALLBACK Dispatcher::staticCallback(cl_event event, cl_int event_command_exec_status, void * user_data) {
	Device * const pDevice = static_cast<Device *>(user_data);
	pDevice->m_parent.onEvent(event, event_command_exec_status, *pDevice);
	clReleaseEvent(event);
}

std::string Dispatcher::formatSpeed(double f) {
	const std::string S = " KMGT";

	unsigned int index = 0;
	while (f > 1000.0f && index < S.size()) {
		f /= 1000.0f;
		++index;
	}

	std::ostringstream ss;
	ss << std::fixed << std::setprecision(3) << (double)f << " " << S[index] << "H/s";
	return ss.str();
}
