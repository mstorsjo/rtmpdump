/*
 *  Copyright (C) 2008-2009 Andrej Stepanchuk
 *  Copyright (C) 2009 Howard Chu
 *
 *  This file is part of librtmp.
 *
 *  librtmp is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1,
 *  or (at your option) any later version.
 *
 *  librtmp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with librtmp see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *  http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif
/* Enable this to get full debugging output */
/* #define _DEBUG */
#define CRYPTO

#ifdef _DEBUG
#undef NODEBUG
#endif

typedef enum
{ LOGCRIT=0, LOGERROR, LOGWARNING, LOGINFO,
  LOGDEBUG, LOGDEBUG2, LOGALL
} AMF_LogLevel;

#define Log	AMF_Log
#define LogHex	AMF_LogHex
#define LogHexString	AMF_LogHexString
#define LogPrintf	AMF_LogPrintf
#define LogSetOutput	AMF_LogSetOutput
#define LogStatus	AMF_LogStatus
#define debuglevel	AMF_debuglevel

extern AMF_LogLevel debuglevel;

void LogSetOutput(FILE *file);
void LogPrintf(const char *format, ...);
void LogStatus(const char *format, ...);
void Log(int level, const char *format, ...);
void LogHex(int level, const char *data, unsigned long len);
void LogHexString(int level, const char *data, unsigned long len);

#ifdef __cplusplus
}
#endif
#endif
