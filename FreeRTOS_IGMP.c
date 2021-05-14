/*
 * FreeRTOS+TCP V2.3.2
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

/**
 * @file FreeRTOS_IGMP.c
 * @brief Implements the optional IGMP functionality of the FreeRTOS+TCP network stack.
 */

/* Standard includes. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_ARP.h"
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_DHCP.h"
#include "NetworkInterface.h"
#include "NetworkBufferManagement.h"
#include "FreeRTOS_DNS.h"
#if ( ipconfigSUPPORT_IP_MULTICAST != 0 )
    #include "FreeRTOS_IGMP.h"
#endif


/* Exclude the entire file if DNS is not enabled. */
#if ( ipconfigSUPPORT_IP_MULTICAST != 0 )

/* IGMP protocol definitions. */
    #define ipIGMP_MEMBERSHIP_QUERY        ( ( uint8_t ) 0x11U )      /**< IGMP membership query. */
    #define ipIGMP_MEMBERSHIP_REPORT_V1    ( ( uint8_t ) 0x12U )      /**< IGMP v1 and v2 membership report. */
    #define ipIGMP_MEMBERSHIP_REPORT_V2    ( ( uint8_t ) 0x16U )      /**< IGMP v1 and v2 membership report. */
    #define ipIGMP_MEMBERSHIP_REPORT_V3    ( ( uint8_t ) 0x22U )      /**< IGMP v3 membership report. */

    #if ( ipconfigBYTE_ORDER == pdFREERTOS_BIG_ENDIAN )
        #define ipIGMP_IP_ADDR             0xE0000001UL
    #else
        #define ipIGMP_IP_ADDR             0x010000E0UL
    #endif /* ipconfigBYTE_ORDER == pdFREERTOS_BIG_ENDIAN */

    #include "pack_struct_start.h"
    struct xIGMP_HEADER
    {
        uint8_t ucTypeOfMessage;   /**< The IGMP type                     0 + 1 = 1 */
        uint8_t ucMaxResponseTime; /**< Maximum time (sec) for responses. 1 + 1 = 2 */
        uint16_t usChecksum;       /**< The checksum of whole IGMP packet 2 + 2 = 4 */
        uint32_t uiGroupAddress;   /**< The multicast group address       4 + 4 = 8 */
    }
    #include "pack_struct_end.h"
    typedef struct xIGMP_HEADER IGMPHeader_t;

    extern ipDECL_CAST_PTR_FUNC_FOR_TYPE( IGMPHeader_t );
    extern ipDECL_CAST_CONST_PTR_FUNC_FOR_TYPE( IGMPHeader_t );


    #include "pack_struct_start.h"
    struct xIGMP_PACKET
    {
        EthernetHeader_t xEthernetHeader; /**< The Ethernet header of an IGMP packet. */
        IPHeader_t xIPHeader;             /**< The IP header of an IGMP packet. */
        IGMPHeader_t xIGMPHeader;         /**< The IGMP header of an IGMP packet. */
    }
    #include "pack_struct_end.h"
    typedef struct xIGMP_PACKET IGMPPacket_t;

    extern ipDECL_CAST_PTR_FUNC_FOR_TYPE( IGMPPacket_t );

/*-----------------------------------------------------------*/

/** @brief IGMP timer. Used for sending asynchronous IGMP reports. */
    static List_t xIGMP_ScheduleList;
    /** @brief IGMP timer. Used for sending asynchronous IGMP reports. */
    IPTimer_t xIGMPTimer;

/*-----------------------------------------------------------*/

    static void vSendIGMP( uint32_t uiBlockTime,
                           uint8_t ucIgmpMsgType,
                           uint8_t ucIgmpRespTime,
                           uint32_t uiMulticastGroup_NBO,
                           uint32_t uiSendToAddr_NBO );

/*-----------------------------------------------------------*/

    void vIGMP_Init( void )
    {
        vListInitialise( &xIGMP_ScheduleList );

        MACAddress_t IGMP_MacAddress;
        vSetMultiCastIPv4MacAddress( ipIGMP_IP_ADDR, IGMP_MacAddress.ucBytes );
        xEMAC_AddMulticastAddress( IGMP_MacAddress.ucBytes );

        IGMPReportDesc_t * pxIRD;
        #if ( ipconfigUSE_LLMNR != 0 )
            if( NULL != ( pxIRD = ipCAST_PTR_TO_TYPE_PTR( IGMPReportDesc_t, pvPortMalloc( sizeof( IGMPReportDesc_t ) ) ) ) )
            {
                listSET_LIST_ITEM_OWNER( &( pxIRD->xListItem ), ( void * ) pxIRD );
                pxIRD->xNumSockets = 0;
                pxIRD->ucCountDown = 0;
                pxIRD->mreq.imr_interface.sin_family = FREERTOS_AF_INET;
                pxIRD->mreq.imr_interface.sin_len = sizeof( struct freertos_sockaddr );
                pxIRD->mreq.imr_interface.sin_addr = FreeRTOS_htonl( 0x00000000U );
                pxIRD->mreq.imr_multiaddr.sin_family = FREERTOS_AF_INET;
                pxIRD->mreq.imr_multiaddr.sin_len = sizeof( struct freertos_sockaddr );
                pxIRD->mreq.imr_multiaddr.sin_addr = ipLLMNR_IP_ADDR;
                BaseType_t bReportItemConsumed = xAddIGMPReportToList( pxIRD );

                if( pdTRUE != bReportItemConsumed )
                {
                    /* This should not happen, but if it does, free the memory that was used */
                    vPortFree( pxIRD );
                    pxIRD = NULL;
                }
            }
        #endif /* ipconfigUSE_LLMNR */
    }

/**
 * @brief Process an IGMP packet.
 *
 * @param[in,out] pxIGMPPacket: The IP packet that contains the IGMP message.
 *
 * @return eReleaseBuffer This function always returns eReleaseBuffer as IGMP frames are
 *                        never responded to immediately.
 */
    eFrameProcessingResult_t eProcessIGMPPacket( NetworkBufferDescriptor_t * const pxNetworkBuffer )
    {
        eFrameProcessingResult_t eReturn = eReleaseBuffer;

        if( pxNetworkBuffer->xDataLength < sizeof( IGMPPacket_t ) )
        {
            return eReleaseBuffer;
        }

        IGMPPacket_t * pxIGMPPacket = ipCAST_PTR_TO_TYPE_PTR( IGMPPacket_t, pxNetworkBuffer->pucEthernetBuffer );

        switch( pxIGMPPacket->xIGMPHeader.ucTypeOfMessage )
        {
            case ipIGMP_MEMBERSHIP_QUERY:
               {
                   extern uint32_t uiNumIGMP_Queries;
                   uiNumIGMP_Queries++;

                   if( pxIGMPPacket->xIGMPHeader.uiGroupAddress == 0U )
                   {
                       /* General query. Schedule reports at random times withing the required response time. */

                       /* Prepare a fake random number in case the random generator fails. */
                       uint32_t uiNonRandomCounter = 1;
                       /* Sanity engforcement. */
                       uint8_t ucMaxRespTime = max( 2, pxIGMPPacket->xIGMPHeader.ucMaxResponseTime );
                       ucMaxRespTime--;
                       /* Now we can safely search for random numbers between 1 and ucMaxRespTime which is 1 or more. */

                       /* Find the next power of 2 that is larger than ucMaxRespTime. The algorithm for 32 bit values is described below:
                        * n--;           // 1101 1101 --> 1101 1100
                        * n |= n >> 1;   // 1101 1100 | 0110 1110 = 1111 1110
                        * n |= n >> 2;   // 1111 1110 | 0011 1111 = 1111 1111
                        * n |= n >> 4;   // ...
                        * n |= n >> 8;
                        * n |= n >> 16;  // 1111 1111 | 1111 1111 = 1111 1111
                        * n++;           // 1111 1111 --> 1 0000 0000
                        * In our case, we don't need the ++ at the end as we need a mask-type value. Since we are skipping the ++ though,
                        * we have to check for zeros again. */
                       uint32_t RandMask = ucMaxRespTime;
                       RandMask--;
                       RandMask |= RandMask >> 1;
                       RandMask |= RandMask >> 2;

                       if( 0 == RandMask )
                       {
                           RandMask = 1;
                       }

                       /* Go through the list of IGMP reports and schedule the reports. Note, the IGMP event is set at 100ms
                        * which corresponds to the increment used in pxIGMPPacket->xIGMPHeader.ucMaxResponseTime.
                        * pxIRD->ucCountDown holds a count in increments of the IGMP event time, so 12 = 1200ms = 1.2s */
                       const ListItem_t * pxIterator;
                       const ListItem_t * xEnd = listGET_END_MARKER( &xIGMP_ScheduleList );
                       IGMPReportDesc_t * pxIRD;

                       for( pxIterator = ( const ListItem_t * ) listGET_NEXT( xEnd );
                            pxIterator != ( const ListItem_t * ) xEnd;
                            pxIterator = ( const ListItem_t * ) listGET_NEXT( pxIterator ) )
                       {
                           pxIRD = ipCAST_PTR_TO_TYPE_PTR( IGMPReportDesc_t, listGET_LIST_ITEM_OWNER( pxIterator ) );

                           /* pxIRD->ucCountDown of zero means the report is not scheduled to be sent. If a report is scheduled, and it's
                            * scheduled time is before pxIGMPPacket->xIGMPHeader.ucMaxResponseTime, there is nothing to be done. If a
                            * report is scheduled past pxIGMPPacket->xIGMPHeader.ucMaxResponseTime, or not cheduled at all, we need
                            * to schedule it for a random time between 0 and pxIGMPPacket->xIGMPHeader.ucMaxResponseTime. */
                           if( ( pxIRD->ucCountDown <= 0 ) || ( pxIRD->ucCountDown >= pxIGMPPacket->xIGMPHeader.ucMaxResponseTime ) )
                           {
                               uint32_t uiRandom;

                               if( xApplicationGetRandomNumber( &( uiRandom ) ) == pdFALSE )
                               {
                                   pxIRD->ucCountDown = uiNonRandomCounter++;

                                   if( uiNonRandomCounter > ucMaxRespTime )
                                   {
                                       uiNonRandomCounter = 1;
                                   }
                               }
                               else
                               {
                                   uiRandom &= RandMask;

                                   if( 0 == uiRandom )
                                   {
                                       uiRandom = 1;
                                   }

                                   while( uiRandom > ucMaxRespTime )
                                   {
                                       uiRandom -= ucMaxRespTime;
                                   }

                                   pxIRD->ucCountDown = ( uint8_t ) uiRandom;
                               }
                           }
                       }
                   }

                   eReturn = eReleaseBuffer;
                   break;
               }

            case ipIGMP_MEMBERSHIP_REPORT_V1:
            case ipIGMP_MEMBERSHIP_REPORT_V2:
            case ipIGMP_MEMBERSHIP_REPORT_V3:
               {
                   extern uint32_t uiNumIGMP_Reports;
                   uiNumIGMP_Reports++;
                   break;
               }

            default:
                break;
        }

        return eReturn;
    }

    void vHandleIGMP_Event( void )
    {
        /* Go through the list of IGMP reports and send anything that needs to be sent. */
        const ListItem_t * pxIterator;
        const ListItem_t * xEnd = listGET_END_MARKER( &xIGMP_ScheduleList );
        IGMPReportDesc_t * pxIRD;

        for( pxIterator = ( const ListItem_t * ) listGET_NEXT( xEnd );
             pxIterator != ( const ListItem_t * ) xEnd;
             pxIterator = ( const ListItem_t * ) listGET_NEXT( pxIterator ) )
        {
            pxIRD = ipCAST_PTR_TO_TYPE_PTR( IGMPReportDesc_t, listGET_LIST_ITEM_OWNER( pxIterator ) );

            if( pxIRD->ucCountDown > 0 )
            {
                if( --pxIRD->ucCountDown == 0 )
                {
                    ( void ) vSendIGMP( 0, ipIGMP_MEMBERSHIP_REPORT_V2, 0, pxIRD->mreq.imr_multiaddr.sin_addr, pxIRD->mreq.imr_multiaddr.sin_addr );
                }
            }
        }
    }

/**
 * @brief Create a IGMP event.
 *
 * @return pdPASS or pdFAIL, depending on whether xSendEventStructToIPTask()
 *         succeeded.
 */
    BaseType_t xSendIGMPEvent( void )
    {
        IPStackEvent_t xEventMessage;
        const TickType_t uxDontBlock = 0U;
        uintptr_t uxOption = 0U;

        xEventMessage.eEventType = eIGMPEvent;
        xEventMessage.pvData = ( void * ) uxOption;

        return xSendEventStructToIPTask( &xEventMessage, uxDontBlock );
    }


/**
 * @brief Removes an IGMP report from the list of reports.
 *
 * @param[in] pMCastGroup: The multicast group descriptor to search for.
 */
    void vRemoveIGMPReportFromList( struct freertos_ip_mreq * pMCastGroup )
    {
        configASSERT( pMCastGroup != NULL );

        const ListItem_t * pxIterator;
        const ListItem_t * xEnd = listGET_END_MARKER( &xIGMP_ScheduleList );
        IGMPReportDesc_t * pxIRD;

        for( pxIterator = ( const ListItem_t * ) listGET_NEXT( xEnd );
             pxIterator != ( const ListItem_t * ) xEnd;
             pxIterator = ( const ListItem_t * ) listGET_NEXT( pxIterator ) )
        {
            pxIRD = ipCAST_PTR_TO_TYPE_PTR( IGMPReportDesc_t, listGET_LIST_ITEM_OWNER( pxIterator ) );

            if( pxIRD->mreq.imr_multiaddr.sin_addr == pMCastGroup->imr_multiaddr.sin_addr )
            {
                /* Found a match. */
                if( pxIRD->xNumSockets > 0 )
                {
                    pxIRD->xNumSockets--;
                }

                if( 0 == pxIRD->xNumSockets )
                {
                    ( void ) uxListRemove( &pxIRD->xListItem );
                    vPortFree( pxIRD );
                }

                break;
            }
        }
    }

/**
 * @brief Adds an IGMP report from the list of reports.
 *
 * @param[in] pMCastGroup: The multicast group descriptor to search for.
 */
    BaseType_t xAddIGMPReportToList( IGMPReportDesc_t * pNewEntry )
    {
        configASSERT( pNewEntry != NULL );

        const ListItem_t * pxIterator;
        const ListItem_t * xEnd = listGET_END_MARKER( &xIGMP_ScheduleList );
        IGMPReportDesc_t * pxIRD;

        for( pxIterator = ( const ListItem_t * ) listGET_NEXT( xEnd );
             pxIterator != ( const ListItem_t * ) xEnd;
             pxIterator = ( const ListItem_t * ) listGET_NEXT( pxIterator ) )
        {
            pxIRD = ipCAST_PTR_TO_TYPE_PTR( IGMPReportDesc_t, listGET_LIST_ITEM_OWNER( pxIterator ) );

            if( pxIRD->mreq.imr_multiaddr.sin_addr == pNewEntry->mreq.imr_multiaddr.sin_addr )
            {
                /* Found a duplicate. */
                pxIRD->xNumSockets++;

                /* Inform the caller that we did NOT consume the item they sent us and that
                 * they are allowed to free it if they so choose. */
                return pdFALSE;
            }
        }

        if( pxIterator == xEnd )
        {
            /* Not found. */
            pNewEntry->xNumSockets = 1;

            /* Schedule an unsolicited report to quickly inform IGMP snooping switches that we want
             * to receive this multicast group. ucCountDown of 1 resulted in the report being sent
             * with source IP of 0.0.0.0, so let's give the stack a few hundred milliseconds. Sending
             * and unsolicited IGMP Report means the socket will begin receiving data almost immediately
             * instead of having to wait for the reception of the next IGMP general query + the random
             * interval dictated by the max response time in that query. */
            uint32_t uiRandom;

            if( pdFALSE == xApplicationGetRandomNumber( &uiRandom ) )
            {
                uiRandom = ( uint32_t ) pNewEntry;
            }

            uiRandom = 2 + ( uiRandom & 0x07U );
            pNewEntry->ucCountDown = uiRandom;
            vListInsertEnd( &xIGMP_ScheduleList, &( pNewEntry->xListItem ) );

            /* Inform the caller that we consumed the item they sent us, so they know
             * not to free it. */
            return pdTRUE;
        }
    }

/**
 * @brief Adds or drops a multicast group to/from a socket.
 *
 * @param[in] pxMulticastGroup: The multicast group descriptor. Also holds the socket that this call is for.
 * @param[in] bAction: eSocketOptAddMembership or eSocketOptDropMembership.
 */
    void vModifyMulticastMembership( MCastGroupDesc_t * pxMulticastGroup,
                                     uint8_t bAction )
    {
        if( ( eSocketOptAddMembership != bAction ) && ( eSocketOptDropMembership != bAction ) )
        {
            return;
        }

        FreeRTOS_Socket_t * pxSocket = pxMulticastGroup->pxSocket;
        uint8_t bFreeInputItem = pdTRUE;
        uint8_t bFreeMatchedItem = pdFALSE;

        /* Go through the list of registered groups and try to locate the group that
         * we are being asked to add or remove. This check prevents adding duplicates.*/
        const ListItem_t * pxIterator;
        const ListItem_t * xEnd = listGET_END_MARKER( &( pxSocket->u.xUDP.xMulticastGroupsList ) );
        MCastGroupDesc_t * pxMCG;

        for( pxIterator = ( const ListItem_t * ) listGET_NEXT( xEnd );
             pxIterator != ( const ListItem_t * ) xEnd;
             pxIterator = ( const ListItem_t * ) listGET_NEXT( pxIterator ) )
        {
            pxMCG = ipCAST_PTR_TO_TYPE_PTR( MCastGroupDesc_t, listGET_LIST_ITEM_OWNER( pxIterator ) );

            if( pxMCG->mreq.imr_multiaddr.sin_addr == pxMulticastGroup->mreq.imr_multiaddr.sin_addr )
            {
                /* Found a match. If we need to remove this address, go ahead.
                 * If we need to add it, it's already there, so just free the the descriptor to prevent memory leaks. */
                if( eSocketOptDropMembership == bAction )
                {
                    ( void ) uxListRemove( &pxMCG->xListItem );

                    /* Defer freeing this list item because when called from vSocketClose, this matching item
                     * is the same as our input parameter item, and we need the input parameter item further
                     * down when informing the network interface driver. */
                    bFreeMatchedItem = pdTRUE;

                    if( pxMulticastGroup == pxMCG )
                    {
                        bFreeInputItem = pdFALSE;
                    }
                }

                break;
            }
        }

        if( eSocketOptAddMembership == bAction )
        {
            if( pxIterator == xEnd )
            {
                /* We are adding an item and we couldn't find an identical one. Simply add it. */
                vListInsertEnd( &( pxSocket->u.xUDP.xMulticastGroupsList ), &( pxMulticastGroup->xListItem ) );
                /* Inform the network driver */
                uint8_t MCastDestMacBytes[ 6 ];
                vSetMultiCastIPv4MacAddress( pxMulticastGroup->mreq.imr_multiaddr.sin_addr, MCastDestMacBytes );
                xEMAC_AddMulticastAddress( MCastDestMacBytes );
                bFreeInputItem = pdFALSE;

                /* Since we've added a multicast group to this socket, we need to prepare an IGMP report
                 * for when we receive an IGMP query. Keep in mind that such a report might already exist.
                 * If such an IGMP report is already present in the list, we will increment it's socket
                 * count and free the report we have here. In either case, the MCastGroupDesc_t that we were
                 * passed, no longer needs to hold a reference to this IGMP report. */
                if( pxMulticastGroup->pxIGMPReportDesc )
                {
                    BaseType_t bReportItemConsumed = xAddIGMPReportToList( pxMulticastGroup->pxIGMPReportDesc );

                    if( pdTRUE != bReportItemConsumed )
                    {
                        /* If adding to the list did not consume the item that we sent, that means a duplicate
                         * was found and its socket count was incremented instead of adding the item we sent.
                         * Free the item that was passed to us. */
                        vPortFree( pxMulticastGroup->pxIGMPReportDesc );
                        pxMulticastGroup->pxIGMPReportDesc = NULL;
                    }
                }
            }
            else
            {
                /* Adding, but found duplicate. No need to inform the network driver. Simply free
                 * the IGMPReportDesc_t */
                if( pxMulticastGroup->pxIGMPReportDesc )
                {
                    vPortFree( pxMulticastGroup->pxIGMPReportDesc );
                    pxMulticastGroup->pxIGMPReportDesc = NULL;
                }
            }
        }
        else
        {
            if( pxIterator == xEnd )
            {
                /* Removing, but no match. No need to inform the network driver. */
            }
            else
            {
                /* Removing and found a match. */
                /* Inform the network driver */
                uint8_t MCastDestMacBytes[ 6 ];
                vSetMultiCastIPv4MacAddress( pxMulticastGroup->mreq.imr_multiaddr.sin_addr, MCastDestMacBytes );
                xEMAC_RemoveMulticastAddress( MCastDestMacBytes );

                /* Lastly, locate the IGMP report for this group. Decrement its socket count and
                 * if it becomes zero, remove it from the list and free it. */
                vRemoveIGMPReportFromList( &( pxMCG->mreq ) );
            }
        }

        /* Free the message that was sent to us. */
        if( bFreeInputItem )
        {
            vPortFree( pxMulticastGroup );
        }

        if( bFreeMatchedItem )
        {
            vPortFree( pxMCG );
        }
    }

    static void vSendIGMP( uint32_t uiBlockTime,
                           uint8_t ucIgmpMsgType,
                           uint8_t ucIgmpRespTime,
                           uint32_t uiMulticastGroup_NBO,
                           uint32_t uiSendToAddr_NBO )
    {
        NetworkBufferDescriptor_t * pxNetworkBuffer;

        pxNetworkBuffer = pxGetNetworkBufferWithDescriptor( sizeof( IGMPPacket_t ), uiBlockTime );

        if( pxNetworkBuffer != NULL )
        {
            IGMPPacket_t * pxIGMPPacket = ( IGMPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer;
            uint16_t usEthType = ipIPv4_FRAME_TYPE;

            /* Fill out the Ethernet header */
            vSetMultiCastIPv4MacAddress( uiSendToAddr_NBO, &pxIGMPPacket->xEthernetHeader.xDestinationAddress );
            memcpy( ( void * ) pxIGMPPacket->xEthernetHeader.xSourceAddress.ucBytes, ( void * ) ipLOCAL_MAC_ADDRESS, ( size_t ) ipMAC_ADDRESS_LENGTH_BYTES );
            memcpy( ( void * ) &pxIGMPPacket->xEthernetHeader.usFrameType, ( void * ) &usEthType, sizeof( uint16_t ) );


            IPHeader_t * pxIPHeader;

            pxIPHeader = &( pxIGMPPacket->xIPHeader );

            /* The checksum can be checked here */
            pxIGMPPacket->xIGMPHeader.ucTypeOfMessage = ucIgmpMsgType;
            pxIGMPPacket->xIGMPHeader.ucMaxResponseTime = ucIgmpRespTime;
            pxIGMPPacket->xIGMPHeader.uiGroupAddress = uiMulticastGroup_NBO;

            pxIPHeader->ulDestinationIPAddress = uiSendToAddr_NBO;
            pxIPHeader->ulSourceIPAddress = *ipLOCAL_IP_ADDRESS_POINTER;
            pxIPHeader->ucProtocol = ipPROTOCOL_IGMP;
            pxIPHeader->usLength = ( uint16_t ) ( 0 + sizeof( IPHeader_t ) + sizeof( IGMPHeader_t ) );
            pxIPHeader->usLength = FreeRTOS_htons( pxIPHeader->usLength );
            pxIPHeader->ucVersionHeaderLength = 0x45U; /*ipIPV4_VERSION_HEADER_LENGTH_MIN; */
            pxIPHeader->ucDifferentiatedServicesCode = 0;
            pxIPHeader->usIdentification = FreeRTOS_ntohs( 0x1234 );
            pxIPHeader->ucTimeToLive = 1;
            pxIPHeader->usHeaderChecksum = 0U;

            /* The stack doesn't support fragments, so the fragment offset field must always be zero.
             * The header was never memset to zero, so set both the fragment offset and fragmentation flags in one go.
             */
            #if ( ipconfigFORCE_IP_DONT_FRAGMENT != 0 )
                pxIPHeader->usFragmentOffset = ipFRAGMENT_FLAGS_DONT_FRAGMENT;
            #else
                pxIPHeader->usFragmentOffset = 0U;
            #endif

            pxIGMPPacket->xIGMPHeader.usChecksum = 0U;
            pxIGMPPacket->xIGMPHeader.usChecksum = usGenerateChecksum( 0U, ( uint8_t * ) &( pxIGMPPacket->xIGMPHeader.ucTypeOfMessage ), ipSIZE_OF_IGMP_HEADER );
            pxIGMPPacket->xIGMPHeader.usChecksum = ~FreeRTOS_htons( pxIGMPPacket->xIGMPHeader.usChecksum );

            #if ( ipconfigDRIVER_INCLUDED_TX_IP_CHECKSUM == 0 )
                {
                    pxIPHeader->usHeaderChecksum = 0U;
                    pxIPHeader->usHeaderChecksum = usGenerateChecksum( 0U, ( uint8_t * ) &( pxIPHeader->ucVersionHeaderLength ), ipSIZE_OF_IPv4_HEADER );
                    pxIPHeader->usHeaderChecksum = ~FreeRTOS_htons( pxIPHeader->usHeaderChecksum );
                }
            #endif

            /* Calculate frame length */
            uint32_t uiFrameLen = sizeof( IGMPPacket_t );
            pxNetworkBuffer->xDataLength = uiFrameLen;
            xNetworkInterfaceOutputToPortX( pxNetworkBuffer, pdTRUE, ETHERNET_PORT_ALL );
        }
    }



/**
 * @brief Cast a given pointer to IGMPPacket_t type pointer.
 */
    ipDECL_CAST_PTR_FUNC_FOR_TYPE( IGMPPacket_t )
    {
        return ( IGMPPacket_t * ) pvArgument;
    }
    /*-----------------------------------------------------------*/


/**
 * @brief Cast a given constant pointer to MCastGroupDesc_t type pointer.
 *
 * @return The casted pointer.
 */
    ipDECL_CAST_PTR_FUNC_FOR_TYPE( MCastGroupDesc_t )
    {
        return ( MCastGroupDesc_t * ) pvArgument;
    }

/**
 * @brief Cast a given constant pointer to IGMPReportDesc_t type pointer.
 *
 * @return The cast pointer.
 */
    ipDECL_CAST_PTR_FUNC_FOR_TYPE( IGMPReportDesc_t )
    {
        return ( IGMPReportDesc_t * ) pvArgument;
    }

/************************************************************************/
/* Test code below this point                                           */
/************************************************************************/
    void vIGMP_SendTestFrame( uint32_t uiBlockTime,
                              uint8_t ucPortID )
    {
        NetworkBufferDescriptor_t * pxNetworkBuffer;

        pxNetworkBuffer = pxGetNetworkBufferWithDescriptor( sizeof( IGMPPacket_t ), uiBlockTime );

        if( pxNetworkBuffer != NULL )
        {
            DebugPrintf( "Sending IGMP Query..." );
            uint32_t IpMCastDest_NBO = FreeRTOS_htonl( 0xE0000001 );
            IGMPPacket_t * pxIGMPPacket = ( IGMPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer;
            uint16_t usEthType = ipIPv4_FRAME_TYPE;

            /* Fill out the Ethernet header */
            vSetMultiCastIPv4MacAddress( IpMCastDest_NBO, &pxIGMPPacket->xEthernetHeader.xDestinationAddress );
/*      memset( ( void * ) pxIGMPPacket->xEthernetHeader.xDestinationAddress.ucBytes , 0xFF, ( size_t ) ipMAC_ADDRESS_LENGTH_BYTES ); */
            memcpy( ( void * ) pxIGMPPacket->xEthernetHeader.xSourceAddress.ucBytes, ( void * ) ipLOCAL_MAC_ADDRESS, ( size_t ) ipMAC_ADDRESS_LENGTH_BYTES );
            memcpy( ( void * ) &pxIGMPPacket->xEthernetHeader.usFrameType, ( void * ) &usEthType, sizeof( uint16_t ) );


            IPHeader_t * pxIPHeader;

            pxIPHeader = &( pxIGMPPacket->xIPHeader );

            /* The checksum can be checked here */
            pxIGMPPacket->xIGMPHeader.ucTypeOfMessage = ( uint8_t ) 0x11U;
            pxIGMPPacket->xIGMPHeader.ucMaxResponseTime = 50; /* 5 sec */
            pxIGMPPacket->xIGMPHeader.uiGroupAddress = 0;

            pxIPHeader->ulDestinationIPAddress = IpMCastDest_NBO;
            pxIPHeader->ulSourceIPAddress = *ipLOCAL_IP_ADDRESS_POINTER;
            pxIPHeader->ucProtocol = ipPROTOCOL_IGMP;
            pxIPHeader->usLength = ( uint16_t ) ( 0 + sizeof( IPHeader_t ) + sizeof( IGMPHeader_t ) );
            pxIPHeader->usLength = FreeRTOS_htons( pxIPHeader->usLength );
            pxIPHeader->ucVersionHeaderLength = 0x45U; /*ipIPV4_VERSION_HEADER_LENGTH_MIN; */
            pxIPHeader->ucDifferentiatedServicesCode = 0;
            pxIPHeader->usIdentification = FreeRTOS_ntohs( 0x1234 );
            pxIPHeader->ucTimeToLive = 1;
            pxIPHeader->usHeaderChecksum = 0U;

            /* The stack doesn't support fragments, so the fragment offset field must always be zero.
             * The header was never memset to zero, so set both the fragment offset and fragmentation flags in one go.
             */
            #if ( ipconfigFORCE_IP_DONT_FRAGMENT != 0 )
                pxIPHeader->usFragmentOffset = ipFRAGMENT_FLAGS_DONT_FRAGMENT;
            #else
                pxIPHeader->usFragmentOffset = 0U;
            #endif

            pxIGMPPacket->xIGMPHeader.usChecksum = 0U;
            pxIGMPPacket->xIGMPHeader.usChecksum = usGenerateChecksum( 0U, ( uint8_t * ) &( pxIGMPPacket->xIGMPHeader.ucTypeOfMessage ), ipSIZE_OF_IGMP_HEADER );
            pxIGMPPacket->xIGMPHeader.usChecksum = ~FreeRTOS_htons( pxIGMPPacket->xIGMPHeader.usChecksum );

            #if ( ipconfigDRIVER_INCLUDED_TX_IP_CHECKSUM == 0 )
                {
                    pxIPHeader->usHeaderChecksum = 0U;
                    pxIPHeader->usHeaderChecksum = usGenerateChecksum( 0U, ( uint8_t * ) &( pxIPHeader->ucVersionHeaderLength ), ipSIZE_OF_IPv4_HEADER );
                    pxIPHeader->usHeaderChecksum = ~FreeRTOS_htons( pxIPHeader->usHeaderChecksum );
                }
            #endif



            /* Calculate frame length */
            uint32_t uiFrameLen = sizeof( IGMPPacket_t );


            pxNetworkBuffer->xDataLength = uiFrameLen;


/*      xNetworkInterfaceOutputToPortX( pxNetworkBuffer, pdTRUE, ucPortID ); */
            xNetworkInterfaceOutputToPortX( pxNetworkBuffer, pdFALSE, ucPortID );

            IPStackEvent_t xStackTxEvent = { eNetworkRxEvent, NULL };
            xStackTxEvent.pvData = pxNetworkBuffer;

            if( xSendEventStructToIPTask( &( xStackTxEvent ), 100 ) != pdPASS )
            {
                vReleaseNetworkBufferAndDescriptor( pxNetworkBuffer );
            }
        }
    }



#endif /* if ( ipconfigSUPPORT_IP_MULTICAST != 0 ) */
