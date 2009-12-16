/*  RTMPDump
 *  Copyright (C) 2009 Andrej Stepanchuk
 *  Copyright (C) 2009 Howard Chu
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with RTMPDump; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *  http://www.gnu.org/copyleft/gpl.html
 *
 */

#define _FILE_OFFSET_BITS	64

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <signal.h> // to catch Ctrl-C
#include <getopt.h>

#ifdef WIN32
#define fseeko fseeko64
#define ftello ftello64
#include <winsock.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#define	SET_BINMODE(f)	setmode(fileno(f), O_BINARY)
#else
#define	SET_BINMODE(f)
#endif

#include "rtmp.h"
#include "log.h"
#include "AMFObject.h"
#include "parseurl.h"

int debuglevel = 1;

using namespace RTMP_LIB;

#define RTMPDUMP_VERSION	"v1.9"

#define RD_SUCCESS		0
#define RD_FAILED		1
#define RD_INCOMPLETE		2

// starts sockets
bool InitSockets() 
{
#ifdef WIN32
        WORD version;
        WSADATA wsaData;

        version = MAKEWORD(1,1);
        return (WSAStartup(version, &wsaData)==0);
#else
	return true;
#endif
}

inline void CleanupSockets() {
#ifdef WIN32
        WSACleanup();
#endif
}

//uint32_t nTimeStamp = 0;

#ifdef _DEBUG
uint32_t debugTS = 0;
int pnum=0;

FILE *netstackdump = 0;
FILE *netstackdump_read = 0;
#endif

uint32_t nIgnoredFlvFrameCounter = 0;
uint32_t nIgnoredFrameCounter = 0;
#define MAX_IGNORED_FRAMES	50

FILE *file = 0;
bool bCtrlC = false;

void sigIntHandler(int sig) {
	bCtrlC = true;
	LogPrintf("Caught signal: %d, cleaning up, just a second...\n", sig);
	// ignore all these signals now and let the connection close
	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
}

int WriteHeader(
	        char **buf,                     // target pointer, maybe preallocated
                unsigned int len                // length of buffer if preallocated
	)
{
        char flvHeader[] = { 'F', 'L', 'V', 0x01,
                             0x05, // video + audio, we finalize later if the value is different
                             0x00, 0x00, 0x00, 0x09,
                             0x00, 0x00, 0x00, 0x00 // first prevTagSize=0
        };

	unsigned int size = sizeof(flvHeader);

	if(size > len) {
        	*buf = (char *)realloc(*buf,  size);
                if(*buf == 0) {
                	Log(LOGERROR, "Couldn't reallocate memory!");
                        return -1; // fatal error
                }
        }
	memcpy(*buf, flvHeader, sizeof(flvHeader));
	return size;
}

// Returns -3 if Play.Close/Stop, -2 if fatal error, -1 if no more media packets, 0 if ignorable error, >0 if there is a media packet
int WriteStream(
		CRTMP* rtmp, 
		char **buf,			// target pointer, maybe preallocated
		unsigned int len, 		// length of buffer if preallocated
		uint32_t *tsm, 			// pointer to timestamp, will contain timestamp of last video packet returned
		bool bResume, 		        // resuming mode, will not write FLV header and compare metaHeader and first kexframe
		bool bLiveStream, 		// live mode, will not report absolute timestamps
		uint32_t nResumeTS,		// resume keyframe timestamp
		char *metaHeader, 		// pointer to meta header (if bResume == TRUE)
		uint32_t nMetaHeaderSize,	// length of meta header, if zero meta header check omitted (if bResume == TRUE)
		char *initialFrame,		// pointer to initial keyframe (no FLV header or tagSize, raw data) (if bResume == TRUE)
		uint8_t initialFrameType,	// initial frame type (audio or video)
		uint32_t nInitialFrameSize,	// length of initial frame in bytes, if zero initial frame check omitted (if bResume == TRUE)
		uint8_t *dataType		// whenever we get a video/audio packet we set an appropriate flag here, this will be later written to the FLV header
	)
{
	static bool bStopIgnoring = false;
	static bool bFoundKeyframe = false;
	static bool bFoundFlvKeyframe = false;

	uint32_t prevTagSize = 0;
	int rtnGetNextMediaPacket = 0;
	RTMPPacket packet;

	rtnGetNextMediaPacket = rtmp->GetNextMediaPacket(packet);
	if(rtnGetNextMediaPacket)
	{
		char *packetBody	= packet.m_body;
		unsigned int nPacketLen	= packet.m_nBodySize;

                // Return -3 if this was completed nicely with invoke message Play.Stop or Play.Complete
                if (rtnGetNextMediaPacket == 2) {
                        Log(LOGDEBUG, "Got Play.Complete or Play.Stop from server. Assuming stream is complete");
                        return -3;
                }

		// skip video info/command packets
		if(packet.m_packetType == 0x09 && 
		   nPacketLen == 2 &&
		((*packetBody & 0xf0) == 0x50)) {
			return 0;
		}

		if(packet.m_packetType == 0x09 && nPacketLen <= 5) {
			Log(LOGWARNING, "ignoring too small video packet: size: %d", nPacketLen);
			return 0;
		}
		if(packet.m_packetType == 0x08 && nPacketLen <= 1) {
			Log(LOGWARNING, "ignoring too small audio packet: size: %d", nPacketLen);
			return 0;
		}
#ifdef _DEBUG
		Log(LOGDEBUG, "type: %02X, size: %d, TS: %d ms, abs TS: %d", packet.m_packetType, nPacketLen, packet.m_nTimeStamp, packet.m_hasAbsTimestamp);
		if(packet.m_packetType == 0x09)
			Log(LOGDEBUG, "frametype: %02X", (*packetBody & 0xf0));
#endif

		// check the header if we get one
		if(bResume && packet.m_nTimeStamp == 0) {
			if(nMetaHeaderSize > 0 && packet.m_packetType == 0x12) {
			
				RTMP_LIB::AMFObject metaObj;
                        	int nRes = metaObj.Decode(packetBody, nPacketLen);
                        	if(nRes >= 0) {
					std::string metastring = metaObj.GetProperty(0).GetString();

                                	if(metastring == "onMetaData") {
						// compare
						if((nMetaHeaderSize != nPacketLen) || 
						   (memcmp(metaHeader, packetBody, nMetaHeaderSize) != 0)) {
							return -2;
						}
					}                     	
				}
			}

			// check first keyframe to make sure we got the right position in the stream!
			// (the first non ignored frame)
			if(nInitialFrameSize > 0) {

				// video or audio data
				if(packet.m_packetType == initialFrameType && nInitialFrameSize == nPacketLen) {
					// we don't compare the sizes since the packet can contain several FLV packets, just make
					// sure the first frame is our keyframe (which we are going to rewrite)
					if(memcmp(initialFrame, packetBody, nInitialFrameSize) == 0) {
						Log(LOGDEBUG, "Checked keyframe successfully!");
						bFoundKeyframe = true;
						return 0; // ignore it! (what about audio data after it? it is handled by ignoring all 0ms frames, see below)
					}
				}

				// hande FLV streams, even though the server resends the keyframe as an extra video packet
				// it is also included in the first FLV stream chunk and we have to compare it and
				// filter it out !!
				//
				if(packet.m_packetType == 0x16) {
					// basically we have to find the keyframe with the correct TS being nResumeTS
					unsigned int pos=0;
					uint32_t ts = 0;

                        		while(pos+11 < nPacketLen) {
                                		uint32_t dataSize = CRTMP::ReadInt24(packetBody+pos+1); // size without header (11) and prevTagSize (4)
                                		ts = CRTMP::ReadInt24(packetBody+pos+4);
                                		ts |= (packetBody[pos+7]<<24);
						
#ifdef _DEBUG	
						Log(LOGDEBUG, "keyframe search: FLV Packet: type %02X, dataSize: %d, timeStamp: %d ms",
						                                                packetBody[pos], dataSize, ts);
#endif
						// ok, is it a keyframe!!!: well doesn't work for audio!
						if(packetBody[pos /*6928, test 0*/] == initialFrameType /* && (packetBody[11]&0xf0) == 0x10*/) {
							if(ts == nResumeTS) {
								Log(LOGDEBUG, "Found keyframe with resume-keyframe timestamp!");
								if(nInitialFrameSize != dataSize || memcmp(initialFrame, packetBody+pos+11, nInitialFrameSize) != 0) {
									Log(LOGERROR, "FLV Stream: Keyframe doesn't match!");
									return -2;
								}
								bFoundFlvKeyframe = true;

								// ok, skip this packet
								// check whether skipable:
								if(pos+11+dataSize+4 > nPacketLen) {
									Log(LOGWARNING, "Non skipable packet since it doesn't end with chunk, stream corrupt!");
									return -2;
								}
								packetBody += (pos+11+dataSize+4);
								nPacketLen -= (pos+11+dataSize+4);

								goto stopKeyframeSearch;

							} else if(nResumeTS < ts) {
								goto stopKeyframeSearch; // the timestamp ts will only increase with further packets, wait for seek
							}
						} 
                                		pos += (11+dataSize+4);
                        		}
					if(ts < nResumeTS) {
						Log(LOGERROR, "First packet does not contain keyframe, all timestamps are smaller than the keyframe timestamp, so probably the resume seek failed?");
					}
stopKeyframeSearch:
					;
					if(!bFoundFlvKeyframe) {
						Log(LOGERROR, "Couldn't find the seeked keyframe in this chunk!");
						return 0;
					}
				}
			}
		}
		
		if(bResume && packet.m_nTimeStamp > 0 && (bFoundFlvKeyframe || bFoundKeyframe)) {
			// another problem is that the server can actually change from 09/08 video/audio packets to an FLV stream
			// or vice versa and our keyframe check will prevent us from going along with the new stream if we resumed
			//
			// in this case set the 'found keyframe' variables to true
			// We assume that if we found one keyframe somewhere and were already beyond TS > 0 we have written
			// data to the output which means we can accept all forthcoming data inclusing the change between 08/09 <-> FLV
			// packets
			bFoundFlvKeyframe = true;
			bFoundKeyframe = true;
		}

                // skip till we find out keyframe (seeking might put us somewhere before it)
		if(bResume && !bFoundKeyframe && packet.m_packetType != 0x16) {
                        Log(LOGWARNING, "Stream does not start with requested frame, ignoring data... ");
                        nIgnoredFrameCounter++;
                        if(nIgnoredFrameCounter > MAX_IGNORED_FRAMES)
                                return -2; // fatal error, couldn't continue stream
                        return 0;
                }
		// ok, do the same for FLV streams
		if(bResume && !bFoundFlvKeyframe && packet.m_packetType == 0x16) {
                        Log(LOGWARNING, "Stream does not start with requested FLV frame, ignoring data... ");
                        nIgnoredFlvFrameCounter++;
                        if(nIgnoredFlvFrameCounter > MAX_IGNORED_FRAMES)
                                return -2;
                        return 0;
                }	

		// if bResume, we continue a stream, we have to ignore the 0ms frames since these are the first keyframes, we've got these
		// so don't mess around with multiple copies sent by the server to us! (if the keyframe is found at a later position
		// there is only one copy and it will be ignored by the preceding if clause)
		if(!bStopIgnoring && bResume && packet.m_packetType != 0x16) { // exclude type 0x16 (FLV) since it can conatin several FLV packets
			if(packet.m_nTimeStamp == 0) {
				return 0;
			} else {
				bStopIgnoring = true; // stop ignoring packets
			}
		}

		// calculate packet size and reallocate buffer if necessary
		unsigned int size = nPacketLen 
			+ ((packet.m_packetType == 0x08 || packet.m_packetType == 0x09 || packet.m_packetType == 0x12) ? 11 : 0)
			+ (packet.m_packetType != 0x16 ? 4 : 0);
		
		if(size+4 > len) { // the extra 4 is for the case of an FLV stream without a last prevTagSize (we need extra 4 bytes to append it)
			*buf = (char *)realloc(*buf, size+4);
			if(*buf == 0) {
				Log(LOGERROR, "Couldn't reallocate memory!");
				return -1; // fatal error
			}
		}
		char *ptr = *buf;

		uint32_t nTimeStamp = 0; // use to return timestamp of last processed packet

		// audio (0x08), video (0x09) or metadata (0x12) packets :
		// construct 11 byte header then add rtmp packet's data
		if(packet.m_packetType == 0x08 || packet.m_packetType == 0x09 || packet.m_packetType == 0x12)
		{
			// set data type
			*dataType |= (((packet.m_packetType == 0x08)<<2)|(packet.m_packetType == 0x09));

			nTimeStamp = nResumeTS + packet.m_nTimeStamp;
			prevTagSize = 11 + nPacketLen;

			*ptr = packet.m_packetType;
			ptr++;
			ptr += CRTMP::EncodeInt24(ptr, nPacketLen);

			/*if(packet.m_packetType == 0x09) { // video

				// H264 fix:
				if((packetBody[0] & 0x0f) == 7) { // CodecId = H264
					uint8_t packetType = *(packetBody+1);
					
					uint32_t ts = CRTMP::ReadInt24(packetBody+2); // composition time
					int32_t cts = (ts+0xff800000)^0xff800000;
					Log(LOGDEBUG, "cts  : %d\n", cts);

					nTimeStamp -= cts;
					// get rid of the composition time
					CRTMP::EncodeInt24(packetBody+2, 0);
				}
				Log(LOGDEBUG, "VIDEO: nTimeStamp: 0x%08X (%d)\n", nTimeStamp, nTimeStamp);
			}*/

			ptr += CRTMP::EncodeInt24(ptr, nTimeStamp);
			*ptr = (char)((nTimeStamp & 0xFF000000) >> 24);
			ptr++;

			// stream id
			ptr += CRTMP::EncodeInt24(ptr, 0);
		}

		memcpy(ptr, packetBody, nPacketLen);
		unsigned int len = nPacketLen;
		
		// correct tagSize and obtain timestamp if we have an FLV stream
		if(packet.m_packetType == 0x16) 
		{
			unsigned int pos=0;

                        while(pos+11 < nPacketLen) 
			{
				uint32_t dataSize = CRTMP::ReadInt24(packetBody+pos+1); // size without header (11) and without prevTagSize (4)
                                nTimeStamp = CRTMP::ReadInt24(packetBody+pos+4);
                                nTimeStamp |= (packetBody[pos+7]<<24);

				/*
				CRTMP::EncodeInt24(ptr+pos+4, nTimeStamp);
				ptr[pos+7] = (nTimeStamp>>24)&0xff;//*/

				// set data type
				*dataType |= (((*(packetBody+pos) == 0x08)<<2)|(*(packetBody+pos) == 0x09));

                                if(pos+11+dataSize+4 > nPacketLen) {
					if(pos+11+dataSize > nPacketLen) {
						Log(LOGERROR, "Wrong data size (%lu), stream corrupted, aborting!", dataSize);
						return -2;
					}
                                	Log(LOGWARNING, "No tagSize found, appending!");
                                                
					// we have to append a last tagSize!
                                        prevTagSize = dataSize+11;
                                        CRTMP::EncodeInt32(ptr+pos+11+dataSize, prevTagSize);
                                        size+=4; len+=4;
                                } else {
                                        prevTagSize = CRTMP::ReadInt32(packetBody+pos+11+dataSize);
                                        
#ifdef _DEBUG
					Log(LOGDEBUG, "FLV Packet: type %02X, dataSize: %lu, tagSize: %lu, timeStamp: %lu ms",
                                                (unsigned char)packetBody[pos], dataSize, prevTagSize, nTimeStamp);
#endif

                                        if(prevTagSize != (dataSize+11)) {
#ifdef _DEBUG
						Log(LOGWARNING, "Tag and data size are not consitent, writing tag size according to dataSize+11: %d", dataSize+11);
#endif

						prevTagSize = dataSize+11;
                                                CRTMP::EncodeInt32(ptr+pos+11+dataSize, prevTagSize);
                                        }
                                }

                                pos += prevTagSize+4;//(11+dataSize+4);
			}
		}
		ptr += len;

		if(packet.m_packetType != 0x16) { // FLV tag packets contain their own prevTagSize
			CRTMP::EncodeInt32(ptr, prevTagSize);
			//ptr += 4;
		}

		// In non-live this nTimeStamp can contain an absolute TS.
		// Update ext timestamp with this absolute offset in non-live mode otherwise report the relative one
		// LogPrintf("\nDEBUG: type: %02X, size: %d, pktTS: %dms, TS: %dms, bLiveStream: %d", packet.m_packetType, nPacketLen, packet.m_nTimeStamp, nTimeStamp, bLiveStream);
		if(tsm)
 			*tsm = bLiveStream ? packet.m_nTimeStamp : nTimeStamp;


		return size;
	}

	return -1; // no more media packets
}

int OpenResumeFile(const char *flvFile,        // file name [in]
		   FILE **file,                // opened file [out]
		   off_t *size,                // size of the file [out]
		   char **metaHeader,          // meta data read from the file [out]
		   uint32_t *nMetaHeaderSize,  // length of metaHeader [out]
		   double *duration)           // duration of the stream in ms [out]
{
	const size_t bufferSize = 1024;
	char buffer[bufferSize];

	*nMetaHeaderSize = 0;
	*size = 0;

	*file = fopen(flvFile, "r+b");
	if (!*file)
		return RD_SUCCESS; // RD_SUCCESS, because we go to fresh file mode instead of quiting
	
	fseek(*file, 0, SEEK_END);
	*size = ftello(*file);
	fseek(*file, 0, SEEK_SET);

	if(*size > 0) {
		// verify FLV format and read header 
		uint32_t prevTagSize = 0;

		// check we've got a valid FLV file to continue!
		if(fread(buffer, 1, 13, *file) != 13) {
			Log(LOGERROR, "Couldn't read FLV file header!");
			return RD_FAILED;
		}
		if(buffer[0] != 'F' || buffer[1] != 'L' || buffer[2] != 'V' || buffer[3] != 0x01) {
			Log(LOGERROR, "Inavlid FLV file!");
			return RD_FAILED;
		}

		if((buffer[4]&0x05) == 0) {
			Log(LOGERROR, "FLV file contains neither video nor audio, aborting!");
			return RD_FAILED;
		}
	
		uint32_t dataOffset = RTMP_LIB::CRTMP::ReadInt32(buffer+5);
		fseek(*file, dataOffset, SEEK_SET);

		if(fread(buffer, 1, 4, *file) != 4) {
			Log(LOGERROR, "Invalid FLV file: missing first prevTagSize!");
			return RD_FAILED;
		}
		prevTagSize = RTMP_LIB::CRTMP::ReadInt32(buffer);
		if(prevTagSize != 0) {
			Log(LOGWARNING, "First prevTagSize is not zero: prevTagSize = 0x%08X", prevTagSize);
		}

		// go through the file to find the meta data!
		off_t pos = dataOffset+4;
		bool bFoundMetaHeader = false;

		while(pos < *size-4 && !bFoundMetaHeader) {
			fseeko(*file, pos, SEEK_SET);
			if(fread(buffer, 1, 4, *file)!=4)
				break;

			uint32_t dataSize = RTMP_LIB::CRTMP::ReadInt24(buffer+1);
				
			if(buffer[0] == 0x12) {
				if (dataSize > bufferSize) {
					Log(LOGERROR, "%s: dataSize (%d) > bufferSize (%d)", __FUNCTION__, dataSize, bufferSize);
					return RD_FAILED;
				}

				fseeko(*file, pos+11, SEEK_SET);
				if(fread(buffer, 1, dataSize, *file) != dataSize)
					break;
				
				RTMP_LIB::AMFObject metaObj;
				int nRes = metaObj.Decode(buffer, dataSize);
				if(nRes < 0) {
					Log(LOGERROR, "%s, error decoding meta data packet", __FUNCTION__);
					break;
				}
					
				std::string metastring = metaObj.GetProperty(0).GetString();

				if(metastring == "onMetaData") {
					metaObj.Dump();
						
					*nMetaHeaderSize = dataSize;
					if (*metaHeader) free(*metaHeader);
					*metaHeader = (char *)malloc(*nMetaHeaderSize);
					memcpy(*metaHeader, buffer, *nMetaHeaderSize);

					// get duration
					AMFObjectProperty prop;
					if(RTMP_LIB::CRTMP::FindFirstMatchingProperty(metaObj, "duration", prop)) {
						*duration = prop.GetNumber();
						Log(LOGDEBUG, "File has duration: %f", *duration);
					}

					bFoundMetaHeader = true;
					break;
				}
				//metaObj.Reset();
				//delete obj;
			}
			pos += (dataSize+11+4);
		}

		if(!bFoundMetaHeader)
			Log(LOGWARNING, "Couldn't locate meta data!");
	}

	return RD_SUCCESS;
}

int GetLastKeyframe(FILE *file,                   // output file [in]
		    int nSkipKeyFrames,           // max number of frames to skip when searching for key frame [in]
		    uint32_t *dSeek,              // offset of the last key frame [out]
		    char **initialFrame,          // content of the last keyframe [out]
		    int *initialFrameType,        // initial frame type (audio/video) [out]
		    uint32_t *nInitialFrameSize)  // length of initialFrame [out]
{
	const size_t bufferSize = 16;
	char buffer[bufferSize];
        uint8_t dataType;
	bool bAudioOnly;
	off_t size;

	fseek(file, 0, SEEK_END);
	size = ftello(file);

        fseek(file, 4, SEEK_SET);
        fread(&dataType, sizeof(uint8_t), 1, file);
        bAudioOnly = (dataType & 0x4) && !(dataType & 0x1);

	Log(LOGDEBUG, "bAudioOnly: %d, size: %llu", bAudioOnly, (unsigned long long)size);

	// ok, we have to get the timestamp of the last keyframe (only keyframes are seekable) / last audio frame (audio only streams) 

		//if(!bAudioOnly) // we have to handle video/video+audio different since we have non-seekable frames
		//{
			// find the last seekable frame
			off_t tsize = 0;
			uint32_t prevTagSize = 0;

			// go through the file and find the last video keyframe
			do {
				int xread;
skipkeyframe:
				if(size-tsize < 13) {
					Log(LOGERROR, "Unexpected start of file, error in tag sizes, couldn't arrive at prevTagSize=0");
					return RD_FAILED;
				}
				fseeko(file, size-tsize-4, SEEK_SET);
				xread = fread(buffer, 1, 4, file);
				if(xread != 4) {
					Log(LOGERROR, "Couldn't read prevTagSize from file!");
					return RD_FAILED;
				}

				prevTagSize = RTMP_LIB::CRTMP::ReadInt32(buffer);
				//Log(LOGDEBUG, "Last packet: prevTagSize: %d", prevTagSize);
				
				if(prevTagSize == 0) {
					Log(LOGERROR, "Couldn't find keyframe to resume from!");
					return RD_FAILED;
				}

				if(prevTagSize < 0 || prevTagSize > size-4-13) {
					Log(LOGERROR, "Last tag size must be greater/equal zero (prevTagSize=%d) and smaller then filesize, corrupt file!", prevTagSize);
					return RD_FAILED;
				}
				tsize += prevTagSize+4;

				// read header
				fseeko(file, size-tsize, SEEK_SET);
				if(fread(buffer, 1, 12, file) != 12) {
					Log(LOGERROR, "Couldn't read header!");
					return RD_FAILED;
				}
				//*
#ifdef _DEBUG
				uint32_t ts = RTMP_LIB::CRTMP::ReadInt24(buffer+4);
				ts |= (buffer[7]<<24);
				Log(LOGDEBUG, "%02X: TS: %d ms", buffer[0], ts);
#endif	//*/

				// this just continues the loop whenever the number of skipped frames is > 0,
				// so we look for the next keyframe to continue with
				//
				// this helps if resuming from the last keyframe fails and one doesn't want to start
				// the download from the beginning
				//
				if(nSkipKeyFrames > 0 && !(!bAudioOnly && (buffer[0] != 0x09 || (buffer[11]&0xf0) != 0x10))) {
					#ifdef _DEBUG
					Log(LOGDEBUG, "xxxxxxxxxxxxxxxxxxxxxxxx Well, lets go one more back!");
					#endif
					nSkipKeyFrames--;
					goto skipkeyframe;
				}

			} while(
				(bAudioOnly && buffer[0] != 0x08) ||
				(!bAudioOnly && (buffer[0] != 0x09 || (buffer[11]&0xf0) != 0x10))
				); // as long as we don't have a keyframe / last audio frame
		
			// save keyframe to compare/find position in stream
			*initialFrameType = buffer[0];
			*nInitialFrameSize = prevTagSize-11;
			*initialFrame = (char *)malloc(*nInitialFrameSize);
			
			fseeko(file, size-tsize+11, SEEK_SET);
			if(fread(*initialFrame, 1, *nInitialFrameSize, file) != *nInitialFrameSize) {
				Log(LOGERROR, "Couldn't read last keyframe, aborting!");
				return RD_FAILED;
			}

			*dSeek = RTMP_LIB::CRTMP::ReadInt24(buffer+4); // set seek position to keyframe tmestamp
			*dSeek |= (buffer[7]<<24);
		//} 
		//else // handle audio only, we can seek anywhere we'd like
		//{
		//}

		if(*dSeek < 0) {
			Log(LOGERROR, "Last keyframe timestamp is negative, aborting, your file is corrupt!");
			return RD_FAILED;
		}
		Log(LOGDEBUG,"Last keyframe found at: %d ms, size: %d, type: %02X", *dSeek, *nInitialFrameSize, *initialFrameType);

		/*
		// now read the timestamp of the frame before the seekable keyframe:
		fseeko(file, size-tsize-4, SEEK_SET);
		if(fread(buffer, 1, 4, file) != 4) {
			Log(LOGERROR, "Couldn't read prevTagSize from file!");
			goto start;
		}
		uint32_t prevTagSize = RTMP_LIB::CRTMP::ReadInt32(buffer);
		fseeko(file, size-tsize-4-prevTagSize+4, SEEK_SET);
		if(fread(buffer, 1, 4, file) != 4) {
			Log(LOGERROR, "Couldn't read previous timestamp!");
			goto start;
                }
		uint32_t timestamp = RTMP_LIB::CRTMP::ReadInt24(buffer);
		timestamp |= (buffer[3]<<24);

		Log(LOGDEBUG, "Previuos timestamp: %d ms", timestamp);
		*/

		if(*dSeek != 0) {
			// seek to position after keyframe in our file (we will ignore the keyframes resent by the server
			// since they are sent a couple of times and handling this would be a mess)
			fseeko(file, size-tsize+prevTagSize+4, SEEK_SET);
			
			// make sure the WriteStream doesn't write headers and ignores all the 0ms TS packets
			// (including several meta data headers and the keyframe we seeked to)
			//bNoHeader = true; if bResume==true this is true anyway
		}

	//}

	return RD_SUCCESS;
}

int Download(CRTMP *rtmp,                      // connected CRTMP object
	     FILE *file,
	     uint32_t dSeek, 
	     uint32_t dLength, 
	     double duration, 
	     bool bResume,
	     char *metaHeader, 
	     uint32_t nMetaHeaderSize, 
	     char *initialFrame, 
	     int initialFrameType, 
	     uint32_t nInitialFrameSize,
	     int nSkipKeyFrames,
	     bool bStdoutMode,
	     bool bLiveStream,
	     bool bHashes,
	     bool bOverrideBufferTime,
	     uint32_t bufferTime,
	     double *percent)                  // percentage downloaded [out]
{
	uint32_t timestamp = dSeek;
	int32_t now, lastUpdate;
	uint8_t dataType = 0;    // will be written into the FLV header (position 4)
	int bufferSize = 1024*1024;
	char *buffer = (char *)malloc(bufferSize);
        int nRead = 0;
	off_t size = ftello(file);
	unsigned long lastPercent = 0;

	memset(buffer, 0, bufferSize);

	*percent = 0.0;

	if(timestamp) {
		Log(LOGDEBUG, "Continuing at TS: %d ms\n", timestamp);
	}

	if(bLiveStream) {
		LogPrintf("Starting Live Stream\n");
	} else {
		// print initial status
		// Workaround to exit with 0 if the file is fully (> 99.9%) downloaded
		if( duration > 0 ) {
			if  ((double)timestamp >= (double)duration*999.0 ) {
				LogPrintf("Already Completed at: %.3f sec Duration=%.3f sec\n", (double)timestamp/1000.0, (double)duration/1000.0);
				return RD_SUCCESS;
			} else {
				*percent = ((double)timestamp) / (duration*1000.0)*100.0;
				*percent = round(*percent*10.0)/10.0;
				LogPrintf("%s download at: %.3f kB / %.3f sec (%.1f%%)\n",
					bResume ? "Resuming":"Starting",
					(double)size/1024.0, (double)timestamp/1000.0, *percent);
			}
		} else {
			LogPrintf("%s download at: %.3f kB\n", bResume ? "Resuming":"Starting",(double)size/1024.0);
		}
	}

	if (dLength > 0)
		LogPrintf("For duration: %.3f sec\n", (double)dLength/1000.0);

	// write FLV header if not resuming
	if(!bResume) {
		nRead = WriteHeader(&buffer, bufferSize);
		if(nRead > 0) {
			if(fwrite(buffer, sizeof(unsigned char), nRead, file) != (size_t)nRead) {
				Log(LOGERROR, "%s: Failed writing FLV header, exiting!", __FUNCTION__);
				free(buffer);
				return RD_FAILED;
			}
			size += nRead;
		} else {
			Log(LOGERROR, "Couldn't obtain FLV header, exiting!");
			free(buffer);
			return RD_FAILED;
		}
	}

	now = GetTime();
	lastUpdate = now-1000;
	do
	{
		nRead = WriteStream(rtmp, &buffer, bufferSize, &timestamp, bResume && nInitialFrameSize > 0, bLiveStream, dSeek, metaHeader, nMetaHeaderSize, initialFrame, initialFrameType, nInitialFrameSize, &dataType);

		//LogPrintf("nRead: %d\n", nRead);
		if(nRead > 0) {
			if(fwrite(buffer, sizeof(unsigned char), nRead, file) != (size_t)nRead) {
				Log(LOGERROR, "%s: Failed writing, exiting!", __FUNCTION__);
				free(buffer);
				return RD_FAILED;
                        }
			size += nRead;
	
			//LogPrintf("write %dbytes (%.1f kB)\n", nRead, nRead/1024.0);
			if(duration <= 0) // if duration unknown try to get it from the stream (onMetaData)
				duration = rtmp->GetDuration();

			if(duration > 0) {
				// make sure we claim to have enough buffer time!
				if(!bOverrideBufferTime && bufferTime < (duration*1000.0)) {
					bufferTime = (uint32_t)(duration*1000.0)+5000; // extra 5sec to make sure we've got enough
					
					Log(LOGDEBUG, "Detected that buffer time is less than duration, resetting to: %dms", bufferTime);
					rtmp->SetBufferMS(bufferTime);
					rtmp->UpdateBufferMS();
				}
				*percent = ((double)timestamp) / (duration*1000.0)*100.0;
				*percent = round(*percent*10.0)/10.0;
				if (bHashes) {
					if ( lastPercent + 1 <= *percent ) {
						LogStatus("#");
						lastPercent = (unsigned long)*percent;
					}
				} else {
					now = GetTime();
					if (abs(now - lastUpdate) > 200) {
						LogStatus("\r%.3f kB / %.2f sec (%.1f%%)", (double)size/1024.0, (double)(timestamp)/1000.0, *percent);
						lastUpdate = now;
					}
				}
			} else {
				now = GetTime();
				if (abs(now - lastUpdate) > 200) {
					if (bHashes)
						LogStatus("#");
					else
						LogStatus("\r%.3f kB / %.2f sec", (double)size/1024.0, (double)(timestamp)/1000.0);
					lastUpdate = now;
				}
			}
		}
#ifdef _DEBUG
		else { Log(LOGDEBUG, "zero read!"); }
#endif

	} while(!bCtrlC && nRead > -1 && rtmp->IsConnected());
	free(buffer);

	Log(LOGDEBUG, "WriteStream returned: %d", nRead);

	if(bResume && nRead == -2) {
		LogPrintf("Couldn't resume FLV file, try --skip %d\n\n", nSkipKeyFrames+1);
		return RD_FAILED;
	}

	// finalize header by writing the correct dataType (video, audio, video+audio)
	if(!bResume && dataType != 0x5 && !bStdoutMode) {
		//Log(LOGDEBUG, "Writing data type: %02X", dataType);
		fseek(file, 4, SEEK_SET);
		fwrite(&dataType, sizeof(unsigned char), 1, file);
	}

	if(nRead == -3)
		return RD_SUCCESS;

	if((duration > 0 && *percent < 99.9) || bCtrlC || nRead < 0 || rtmp->IsTimedout()) {
		return RD_INCOMPLETE;
	}

	return RD_SUCCESS;
}

//#define _DEBUG_TEST_PLAYSTOP

int main(int argc, char **argv)
{
	extern char *optarg;

//#ifdef _DEBUG_TEST_PLAYSTOP
//	RTMPPacket packet;
//#endif
	int nStatus = RD_SUCCESS;
	double percent = 0;
	double duration = 0.0;


	int nSkipKeyFrames = 0;  // skip this number of keyframes when resuming

	bool bOverrideBufferTime = false; // if the user specifies a buffer time override this is true
	bool bStdoutMode = true;// if true print the stream directly to stdout, messages go to stderr
	bool bResume = false;    // true in resume mode
	uint32_t dSeek = 0;	 // seek position in resume mode, 0 otherwise
	uint32_t bufferTime = 10*60*60*1000; // 10 hours as default

	// meta header and initial frame for the resume mode (they are read from the file and compared with
	// the stream we are trying to continue
	char *metaHeader = 0;
	uint32_t nMetaHeaderSize = 0;
	
	// video keyframe for matching
	char *initialFrame = 0;
	uint32_t nInitialFrameSize = 0;
	int initialFrameType = 0; // tye: audio or video

	char *hostname = 0;
	char *playpath = 0;
	char *subscribepath = 0;
	int port = -1;
	int protocol = RTMP_PROTOCOL_UNDEFINED;
	bool bLiveStream = false; // is it a live stream? then we can't seek/resume
	bool bHashes = false; // display byte counters not hashes by default

	long int timeout = 120; // timeout connection after 120 seconds
	uint32_t dStartOffset = 0; // seek position in non-live mode
	uint32_t dStopOffset = 0;
	uint32_t dLength = 0; // length to play from stream - calculated from seek position and dStopOffset

	char *rtmpurl = 0;
	char *swfUrl = 0;
	char *tcUrl = 0;
	char *pageUrl = 0;
	char *app = 0;
	char *auth = 0;
	char *swfHash = 0;
	uint32_t swfSize = 0;
	char *flashVer = 0;
        char *sockshost = 0;

	char *flvFile = 0;

	char DEFAULT_FLASH_VER[]  = "LNX 10,0,22,87";
	
	signal(SIGHUP, sigIntHandler);
	signal(SIGINT, sigIntHandler);
	signal(SIGPIPE, sigIntHandler);
	signal(SIGTERM, sigIntHandler);
	signal(SIGQUIT, sigIntHandler);

	/* sleep(30); */

	// Check for --quiet option before printing any output
	int index = 0;
       	while (index < argc)
	{
		if ( strcmp( argv[index], "--quiet")==0 || strcmp( argv[index], "-q")==0 )
			debuglevel = LOGCRIT;
		index++;
	}

 	LogPrintf("RTMPDump %s\n", RTMPDUMP_VERSION);
	LogPrintf("(c) 2009 Andrej Stepanchuk, Howard Chu, The Flvstreamer Team; license: GPL\n");

	int opt;
	struct option longopts[] = {
		{"help",    0, NULL, 'h'},
		{"host",    1, NULL, 'n'},
		{"port",    1, NULL, 'c'},
		{"socks",   1, NULL, 'S'},
		{"protocol",1, NULL, 'l'},
		{"playpath",1, NULL, 'y'},
		{"rtmp",    1, NULL, 'r'},
		{"swfUrl",  1, NULL, 's'},
		{"tcUrl",   1, NULL, 't'},
		{"pageUrl", 1, NULL, 'p'},
		{"app",     1, NULL, 'a'},
		{"auth",    1, NULL, 'u'},
#ifdef CRYPTO
		{"swfhash", 1, NULL, 'w'},
		{"swfsize", 1, NULL, 'x'},
#endif
		{"flashVer",1, NULL, 'f'},
		{"live"	   ,0, NULL, 'v'},
		{"flv",     1, NULL, 'o'},
		{"resume",  0, NULL, 'e'},
		{"timeout", 1, NULL, 'm'},
		{"buffer",  1, NULL, 'b'},
		{"skip",    1, NULL, 'k'},
		{"subscribe",1,NULL, 'd'},
		{"start",   1, NULL, 'A'},
		{"stop",    1, NULL, 'B'},
		{"hashes",  0, NULL, '#'},
		{"debug",   0, NULL, 'z'},
		{"quiet",   0, NULL, 'q'},
		{"verbose", 0, NULL, 'V'},
		{0,0,0,0}
	};

	while((opt = getopt_long(argc, argv, "hVveqzr:s:t:p:a:b:f:o:u:n:c:l:y:m:k:d:A:B:w:x:S:#", longopts, NULL)) != -1) {
		switch(opt) {
			case 'h':
				LogPrintf("\nThis program dumps the media content streamed over rtmp.\n\n");
				LogPrintf("--help|-h               Prints this help screen.\n");
				LogPrintf("--rtmp|-r url           URL (e.g. rtmp//hotname[:port]/path)\n");
				LogPrintf("--host|-n hostname      Overrides the hostname in the rtmp url\n");
				LogPrintf("--port|-c port          Overrides the port in the rtmp url\n");
				LogPrintf("--socks|-S host:port    Use the specified SOCKS proxy\n");
				LogPrintf("--protocol|-l           Overrides the protocol in the rtmp url (0 - RTMP, 3 - RTMPE)\n");
				LogPrintf("--playpath|-y           Overrides the playpath parsed from rtmp url\n");
				LogPrintf("--swfUrl|-s url         URL to player swf file\n");
				LogPrintf("--tcUrl|-t url          URL to played stream (default: \"rtmp://host[:port]/app\")\n");
				LogPrintf("--pageUrl|-p url        Web URL of played programme\n");
				LogPrintf("--app|-a app            Name of player used\n");
#ifdef CRYPTO
				LogPrintf("--swfhash|-w hexstring  SHA256 hash of the decompressed SWF file (32 bytes)\n");
				LogPrintf("--swfsize|-x num        Size of the decompressed SWF file, required for SWFVerification\n");
#endif
				LogPrintf("--auth|-u string        Authentication string to be appended to the connect string\n");
				LogPrintf("--flashVer|-f string    Flash version string (default: \"%s\")\n", DEFAULT_FLASH_VER);
				LogPrintf("--live|-v               Save a live stream, no --resume (seeking) of live streams possible\n");
				LogPrintf("--subscribe|-d string   Stream name to subscribe to (otherwise defaults to playpath if live is specifed)\n");
				LogPrintf("--flv|-o string         FLV output file name, if the file name is - print stream to stdout\n");
				LogPrintf("--resume|-e             Resume a partial RTMP download\n");
				LogPrintf("--timeout|-m num        Timeout connection num seconds (default: %lu)\n", timeout);
				LogPrintf("--start|-A num          Start at num seconds into stream (not valid when using --live)\n");
				LogPrintf("--stop|-B num           Stop at num seconds into stream\n");
				LogPrintf("--hashes|-#             Display progress with hashes, not with the byte counter\n");
				LogPrintf("--buffer|-b             Buffer time in milliseconds (default: %lu), this option makes only sense in stdout mode (-o -)\n", 
					bufferTime);
				LogPrintf("--skip|-k num           Skip num keyframes when looking for last keyframe to resume from. Useful if resume fails (default: %d)\n\n",
					nSkipKeyFrames);
				LogPrintf("--quiet|-q              Supresses all command output.\n");
				LogPrintf("--verbose|-V            Verbose command output.\n");
				LogPrintf("--debug|-z              Debug level command output.\n");
				LogPrintf("If you don't pass parameters for swfUrl, pageUrl, app or auth these propertiews will not be included in the connect ");
				LogPrintf("packet.\n\n");
				return RD_SUCCESS;
#ifdef CRYPTO
			case 'w':
			{
				int res = hex2bin(optarg, &swfHash);
				if(res!=32) {
					swfHash = NULL;
					Log(LOGWARNING, "Couldn't parse swf hash hex string, not heyxstring or not 32 bytes, ignoring!");
				}
				break;
			}
			case 'x':
			{
				int size = atoi(optarg);
				if(size <= 0) {
					Log(LOGERROR, "SWF Size must be at least 1, ignoring\n");
				} else {
					swfSize = size;
				}
				break;
			}
#endif
			case 'k':
				nSkipKeyFrames = atoi(optarg);
				if(nSkipKeyFrames < 0) {
					Log(LOGERROR, "Number of keyframes skipped must be greater or equal zero, using zero!");
					nSkipKeyFrames = 0;
				} else {
					Log(LOGDEBUG, "Number of skipped key frames for resume: %d", nSkipKeyFrames);
				}
				break;
			case 'b':
			{
				int32_t bt = atol(optarg);
				if(bt < 0) {
					Log(LOGERROR, "Buffer time must be greater than zero, ignoring the specified value %d!", bt);
				} else {
					bufferTime = bt;
					bOverrideBufferTime = true;
				}
				break;
			}
			case 'v':
				bLiveStream = true; // no seeking or resuming possible!
				break;
			case 'd':
				subscribepath = optarg;
				break;
			case 'n':
				hostname = optarg;
				break;
			case 'c':
				port = atoi(optarg);
				break;
			case 'l':
				protocol = atoi(optarg);
				if(protocol != RTMP_PROTOCOL_RTMP && protocol != RTMP_PROTOCOL_RTMPE) {
					Log(LOGERROR, "Unknown protocol specified: %d", protocol);
					return RD_FAILED;
				}
				break;
			case 'y':
				playpath = optarg;
				break;
			case 'r':
			{
				rtmpurl = optarg;

				char *parsedHost = 0;
				unsigned int parsedPort = 0;
				char *parsedPlaypath = 0;
				char *parsedApp = 0;
				int parsedProtocol = RTMP_PROTOCOL_UNDEFINED;

				if(!ParseUrl(rtmpurl, &parsedProtocol, &parsedHost, &parsedPort, &parsedPlaypath, &parsedApp)) {
					Log(LOGWARNING, "Couldn't parse the specified url (%s)!", optarg);
				} else {
					if(hostname == 0)
						hostname = parsedHost;
					if(port == -1)
						port = parsedPort;
					if(playpath == 0)
						playpath = parsedPlaypath;
					if(protocol == RTMP_PROTOCOL_UNDEFINED)
						protocol = parsedProtocol;
					if(app == 0)
						app = parsedApp;
				}
				break;
			}
			case 's':
				swfUrl = optarg;
				break;
			case 't':
				tcUrl = optarg;
				break;
			case 'p':
				pageUrl = optarg;
				break;
			case 'a':
				app = optarg;
				break;
			case 'f':
				flashVer = optarg;
				break;
			case 'o':
				flvFile = optarg;
				if(strcmp(flvFile, "-"))
					bStdoutMode = false;

				break;
			case 'e':
				bResume = true;
				break;
			case 'u':
				auth = optarg;		
				break;
			case 'm':
				timeout = atoi(optarg);
				break;
			case 'A':
				dStartOffset = int(atof(optarg)*1000.0);
				break;
			case 'B':
				dStopOffset = int(atof(optarg)*1000.0);
				break;
			case '#':
				bHashes = true;
				break;
			case 'q':
				debuglevel = LOGCRIT;
				break;
			case 'V':
				debuglevel = LOGDEBUG;
				break;
			case 'z':
				debuglevel = LOGALL;
				break;
                        case 'S':
                                sockshost = optarg;
				break;
			default:
				LogPrintf("unknown option: %c\n", opt);
				break;
		}
	}

	if(hostname == 0) {
		Log(LOGERROR, "You must specify a hostname (--host) or url (-r \"rtmp://host[:port]/playpath\") containing a hostname");
		return RD_FAILED;
	}
	if(playpath == 0) {
		Log(LOGERROR, "You must specify a playpath (--playpath) or url (-r \"rtmp://host[:port]/playpath\") containing a playpath");
		return RD_FAILED;
	}
		
	if(port == -1) {
		Log(LOGWARNING, "You haven't specified a port (--port) or rtmp url (-r), using default port 1935");
		port = 1935;
	}
	if(port == 0) {
		port = 1935;
	}
	if(protocol == RTMP_PROTOCOL_UNDEFINED) {
		Log(LOGWARNING, "You haven't specified a protocol (--protocol) or rtmp url (-r), using default protocol RTMP");
		protocol = RTMP_PROTOCOL_RTMP;
	}
	if(flvFile == 0) {
		Log(LOGWARNING, "You haven't specified an output file (-o filename), using stdout");
		bStdoutMode = true;
	}

	if(bStdoutMode && bResume) {
		Log(LOGWARNING, "Can't resume in stdout mode, ignoring --resume option");
		bResume = false;
	}

	if(bLiveStream && bResume) {
		Log(LOGWARNING, "Can't resume live stream, ignoring --resume option");
		bResume = false;
	}

	if(swfHash == 0 && swfSize > 0) {
		Log(LOGWARNING, "Ignoring SWF size, supply also the hash with --swfhash");
		swfSize=0;
	}

	if(swfHash != 0 && swfSize == 0) {
		Log(LOGWARNING, "Ignoring SWF hash, supply also the swf size  with --swfsize");
		swfHash=NULL;
	}

	if(flashVer == 0)
		flashVer = DEFAULT_FLASH_VER;

	if(!InitSockets()) {
		Log(LOGERROR, "Couldn't load sockets support on your platform, exiting!");
		return RD_FAILED;
	}

	if(tcUrl == 0 && app != 0) {
		char str[512]={0};

		/*
		struct hostent *h = gethostbyname(hostname);
		if(h == NULL || h->h_addr == NULL) {
			Log(LOGERROR, "DNS name resolution failed, exiting");
			return RD_FAILED;
		}
		hostip = inet_ntoa(*(struct in_addr*)h->h_addr)
		//*/
		snprintf(str, 511, "%s://%s:%d/%s", RTMPProtocolStringsLower[protocol], hostname, port, app);
		tcUrl = (char *)malloc(strlen(str)+1);
		strcpy(tcUrl, str);
	}

	int first = 1;

	// User defined seek offset
	if (dStartOffset > 0) {
	        // Live stream
	        if (bLiveStream) {
                	Log(LOGWARNING, "Can't seek in a live stream, ignoring --start option");
                	dStartOffset = 0;
                }
        }

	CRTMP  *rtmp = new CRTMP();
	rtmp->SetupStream(protocol, hostname, port, sockshost, playpath, tcUrl, swfUrl,
		pageUrl, app, auth, swfHash, swfSize, flashVer, subscribepath,
		dSeek, 0, bLiveStream, timeout);

	off_t size = 0;

	// ok, we have to get the timestamp of the last keyframe (only keyframes are seekable) / last audio frame (audio only streams) 
	if(bResume) {
		nStatus = OpenResumeFile(flvFile, &file, &size, &metaHeader, &nMetaHeaderSize, &duration);
		if (nStatus == RD_FAILED)
			goto clean;

		if (!file) {
			// file does not exist, so go back into normal mode
			bResume = false; // we are back in fresh file mode (otherwise finalizing file won't be done)
		} else {
			nStatus = GetLastKeyframe(file, nSkipKeyFrames,
						  &dSeek, &initialFrame,
						  &initialFrameType,
						  &nInitialFrameSize);
			if (nStatus == RD_FAILED) {
				Log(LOGDEBUG, "Failed to get last keyframe.");
				goto clean;
			}

			if (dSeek == 0) {
				Log(LOGDEBUG, "Last keyframe is first frame in stream, switching from resume to normal mode!");
				bResume = false;
			}
		}
	}

	if (!file) {
		if(bStdoutMode) {
			file = stdout;
			SET_BINMODE(file);
		} else
		{
			file = fopen(flvFile, "w+b");
			if(file == 0) {
                        	LogPrintf("Failed to open file! %s\n", flvFile);
                        	return RD_FAILED;
                	}
		}
	}
       
#ifdef _DEBUG
	netstackdump = fopen("netstackdump", "wb");
	netstackdump_read = fopen("netstackdump_read", "wb");
#endif

	while (!bCtrlC) {
		Log(LOGDEBUG, "Setting buffer time to: %dms", bufferTime);
		rtmp->SetBufferMS(bufferTime);

		if (first) {
			first = 0;
			LogPrintf("Connecting ...\n");

			if (!rtmp->Connect()) {
				nStatus = RD_FAILED;
				break;
			}

			Log(LOGINFO, "Connected...");

			// User defined seek offset
			if (dStartOffset > 0) {
				// Don't need the start offset if resuming an existing file
				if (bResume) {
					Log(LOGWARNING, "Can't seek a resumed stream, ignoring --start option");
					dStartOffset = 0;
				} else {
					dSeek = dStartOffset;
				}
			}

		        // Calculate the length of the stream to still play
			if (dStopOffset > 0) {
				dLength = dStopOffset - dSeek;

				// Quit if start seek is past required stop offset
				if(dLength <= 0) {
					LogPrintf("Already Completed\n");
					nStatus = RD_SUCCESS;
					break;
				}
			}

			if (!rtmp->ConnectStream(dSeek, dLength)) {
				nStatus = RD_FAILED;
				break;
			}
		} else {
			nInitialFrameSize = 0;

			Log(LOGINFO, "Connection timed out, trying to resume.\n\n");
			if (!rtmp->ToggleStream()) {
				Log(LOGERROR, "Failed to resume the stream\n\n");
				if (!rtmp->IsTimedout())
				  nStatus = RD_FAILED;
				else
				  nStatus = RD_INCOMPLETE;
				break;
			}
			bResume = true;
		}

		nStatus = Download(rtmp, file, dSeek, dLength, duration, bResume,
                           metaHeader, nMetaHeaderSize, initialFrame,
                           initialFrameType, nInitialFrameSize,
                           nSkipKeyFrames, bStdoutMode, bLiveStream, bHashes,
                           bOverrideBufferTime, bufferTime, &percent);
		free(initialFrame);
		initialFrame = NULL;

		/* If we succeeded, we're done.
		 */
		if (nStatus != RD_INCOMPLETE || !rtmp->IsTimedout() || bLiveStream)
			break;
	}

	if (nStatus == RD_SUCCESS) {
		LogPrintf("Download complete\n");
	} else if (nStatus == RD_INCOMPLETE)  {
		LogPrintf("Download may be incomplete (downloaded about %.2f%%), try resuming\n", percent);
	}

clean:
	Log(LOGDEBUG, "Closing connection.\n");
	rtmp->Close();
	//LogPrintf("done!\n\n");

	if(file != 0)
		fclose(file);

	CleanupSockets();

#ifdef _DEBUG
	if(netstackdump != 0)
		fclose(netstackdump);
	if(netstackdump_read != 0)
                fclose(netstackdump_read);	
#endif
	delete rtmp;
	return nStatus;
}

