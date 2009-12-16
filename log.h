/*  RTMP Dump
 *  Copyright (C) 2008-2009 Andrej Stepanchuk
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

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif
// Enable this to get full debugging output
//#define _DEBUG
#define CRYPTO

#ifdef _DEBUG
#undef NODEBUG
#endif

#define LOGCRIT         0
#define LOGERROR        1
#define LOGWARNING	2
#define LOGINFO		3
#define LOGDEBUG		4
#define LOGALL		5

void LogSetOutput(FILE *file);
void LogPrintf(const char *format, ...);
void LogStatus(const char *format, ...);
void Log(int level, const char *format, ...);
void LogHex(int level, const char *data, unsigned long len);
void LogHexString(const char *data, unsigned long len);

#ifdef __cplusplus
}
#endif
#endif
