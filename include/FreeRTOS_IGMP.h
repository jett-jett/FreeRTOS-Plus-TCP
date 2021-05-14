/*
 * FreeRTOS+TCP V2.3.3
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

#ifndef FREERTOS_IGMP_H
    #define FREERTOS_IGMP_H

    #ifdef __cplusplus
        extern "C" {
    #endif

/* Application level configuration options. */
    #include "FreeRTOSIPConfig.h"
    #include "FreeRTOSIPConfigDefaults.h"
    #include "FreeRTOS_Sockets.h"
    #include "IPTraceMacroDefaults.h"
    #include "FreeRTOS_Stream_Buffer.h"
    #if ( ipconfigUSE_TCP == 1 )
        #include "FreeRTOS_TCP_WIN.h"
        #include "FreeRTOS_TCP_IP.h"
    #endif

    #include "semphr.h"

    #include "event_groups.h"


/** @brief IGMP times events at 100ms. */
    #define ipIGMP_TIMER_PERIOD_MS    ( 100U )

    struct freertos_ip_mreq
    {
        /* _EVP_ This can be simplified a bit on a single IF, IPv4 only system
         * but keeping it more generic allows for future use in multi-IF dual-stack implementations. */
        struct freertos_sockaddr imr_multiaddr; /* IP multicast address of a group */
        struct freertos_sockaddr imr_interface; /* local IP address of the interface to be used */
    };

/** @brief The structure information about the IGMP reports that will get sent when the stack receives an IGMP general query. */
    typedef struct xIGMPReportDesc
    {
        struct freertos_ip_mreq mreq; /**< Struct for storing the original mreq structure that was sent to setsockopts() */
        struct xLIST_ITEM xListItem;  /**< List struct. */
        BaseType_t xNumSockets;
        uint8_t ucCountDown;
    } IGMPReportDesc_t;

    extern ipDECL_CAST_PTR_FUNC_FOR_TYPE( IGMPReportDesc_t );
    /** @brief The structure to hold a "descriptor" for a multicast group that a socket has registered to. */
    typedef struct xMCastGroupDesc
    {
        struct freertos_ip_mreq mreq;        /**< Struct for storing the original mreq structure that was sent to setsockopts() */
        struct xLIST_ITEM xListItem;         /**< List struct. */
        FreeRTOS_Socket_t * pxSocket;
        IGMPReportDesc_t * pxIGMPReportDesc; /** Optional. used to hold the allocated IGMP report descriptor while passing from user code to the IP Task. */
    } MCastGroupDesc_t;

    extern ipDECL_CAST_PTR_FUNC_FOR_TYPE( MCastGroupDesc_t );

    extern IPTimer_t xIGMPTimer;

    void vIGMP_Init( void );
    void vModifyMulticastMembership( MCastGroupDesc_t * pxMulticastGroup,
                                     uint8_t bAction );
    BaseType_t xSendIGMPEvent( void );
    void vHandleIGMP_Event( void );
    void vRemoveIGMPReportFromList( struct freertos_ip_mreq * pMCastGroup );
    BaseType_t xAddIGMPReportToList( IGMPReportDesc_t * pNewEntry );
    eFrameProcessingResult_t eProcessIGMPPacket( NetworkBufferDescriptor_t * const pxNetworkBuffer );


    #ifdef __cplusplus
        } /* extern "C" */
    #endif

#endif /* FREERTOS_IP_PRIVATE_H */
