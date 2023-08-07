#include "Samples.h"

static STATUS freeFrameData(PFrame pFrame)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pFrame != NULL, STATUS_NULL_ARG);

    if (pFrame->frameData) {
        MEMFREE(pFrame->frameData);
        pFrame->frameData = NULL;
    }

CleanUp:

    return retStatus;
}

static STATUS doubleListClearRep(PDoubleList pList)
{
    STATUS retStatus = STATUS_SUCCESS;
    PDoubleListNode pCurNode = NULL;
    PDoubleListNode pNextNode = NULL;

    CHK(pList != NULL, STATUS_NULL_ARG);

    pCurNode = pList->pHead;

    while (pCurNode != NULL) {
        pNextNode = pCurNode->pNext;
        if ((PVOID) pCurNode->data != NULL) {
            freeFrameData((PFrame) pCurNode->data);
        }
        MEMFREE(pCurNode);
        pCurNode = pNextNode;
    }

    // Reset the list
    pList->count = 0;
    pList->pHead = pList->pTail = NULL;
CleanUp:

    return retStatus;
}

PFrameBuffer initFrameBuffer(BOOL revFlag, UINT16 max)
{
    STATUS retStatus = STATUS_SUCCESS;
    PFrameBuffer pBuf = NULL;

    pBuf = (PFrameBuffer) MEMALLOC (sizeof(FrameBuffer));
    if (pBuf) {
        pBuf->recvFlag = revFlag;
        pBuf->maxSize = max;
        pBuf->lastConsumedFrameId = 0;
        pBuf->nextConsumedFrameId = 0;
        pBuf->headerFrameId = 0;
        pBuf->tailFrameId = 0;
        pBuf->cond = CVAR_CREATE();
        pBuf->mutex = MUTEX_CREATE(FALSE);
        CHK_STATUS(doubleListCreate(&pBuf->pFrameList));
        pBuf->pFrameList->count = 0;
        pBuf->pFrameList->pHead = NULL;
        pBuf->pFrameList->pTail = NULL;
    }

CleanUp:
    if (retStatus != STATUS_SUCCESS) {
        DLOGE("doubleListCreate failed");
        if (pBuf->pFrameList) {
            doubleListFree(pBuf->pFrameList);
        }

        if (pBuf->cond) {
            CVAR_FREE(pBuf->cond);
        }

        if (pBuf->mutex) {
            MUTEX_FREE(pBuf->mutex);
        }

        if (pBuf) {
            MEMFREE(pBuf);
        }
    }

    return pBuf;
}

STATUS deInitFrameBuffer(BOOL revFlag, PFrameBuffer pBuf)
{
    STATUS retStatus = STATUS_SUCCESS;
    CHK(pBuf != NULL, STATUS_NULL_ARG);
    if (pBuf->pFrameList) {
        doubleListClearRep(pBuf->pFrameList);
        doubleListFree(pBuf->pFrameList);
    }

    if (pBuf->cond) {
        CVAR_SIGNAL(pBuf->cond);
        CVAR_FREE(pBuf->cond);
    }

    if (pBuf->mutex) {
        MUTEX_FREE(pBuf->mutex);
    }

    if (pBuf) {
        MEMFREE(pBuf);
    }

CleanUp:

    return retStatus;
}

STATUS pushFrame(PFrameBuffer pBuf, PFrame pFrame)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 count = 0, hIndex = 0, tIndex = 0;;
    BOOL locked = FALSE;
    PFrame pNewFrame = NULL, pCurFrame = NULL, pNextFrame = NULL;;
    PDoubleListNode pCurNode = NULL, pNextNode = NULL, pPrevNode = NULL;;

    CHK(pFrame != NULL && pBuf != NULL && pBuf->pFrameList != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pBuf->mutex);
    locked = TRUE;

    doubleListGetNodeCount(pBuf->pFrameList, &count);
    if (count >= pBuf->maxSize) {
        doubleListClearRep(pBuf->pFrameList);
        DLOGW("Frame buffer list 0x%x is full, so free all data in buffer", pBuf);
    }

    pNewFrame = (PFrame) MEMALLOC (sizeof(Frame));
    CHK(pNewFrame != NULL, STATUS_NULL_ARG);

    pNewFrame->version = pFrame->version;
    pNewFrame->decodingTs = pFrame->decodingTs;
    pNewFrame->presentationTs = pFrame->presentationTs;
    pNewFrame->size = pFrame->size;
    pNewFrame->duration = pFrame->duration;
    pNewFrame->index = pFrame->index;
    CHK(pNewFrame->size > 0, STATUS_NULL_ARG);
    pNewFrame->frameData = (PBYTE) MEMALLOC (sizeof(PBYTE) * pNewFrame->size);
    CHK(pNewFrame->frameData != NULL, STATUS_NULL_ARG);
    MEMCPY(pNewFrame->frameData, pFrame->frameData, pNewFrame->size);

    if (pBuf->recvFlag) {
        if (pBuf->pFrameList->pHead == NULL && pBuf->pFrameList->pTail == NULL) {
            // Insert the first received frame into frame list.
            CHK_STATUS(doubleListInsertItemHead(pBuf->pFrameList, (UINT64)pNewFrame));
            pBuf->headerFrameId = pNewFrame->index;
            pBuf->tailFrameId = pNewFrame->index;
        } else if (pNewFrame->index < pBuf->nextConsumedFrameId) {
            // If a frame is older than frame which will be consumed next time by frame consumer, then drop it.
            DLOGW("The frame is older, then drop it");
        } else if (pNewFrame->index < pBuf->headerFrameId && pNewFrame->index >= pBuf->nextConsumedFrameId) {
            // A frame is older than frame list header and is newer than which has been consumed by frame consumer,
            // then insert it into list header.
            CHK_STATUS(doubleListInsertItemHead(pBuf->pFrameList, (UINT64)pNewFrame));
            pBuf->headerFrameId = pNewFrame->index;
        } else if (pNewFrame->index > pBuf->tailFrameId) {
            // A frame is newer than newest frame in frame list, then insert it after now tail
            CHK_STATUS(doubleListInsertItemTail(pBuf->pFrameList, (UINT64)pNewFrame));
            pBuf->tailFrameId = pNewFrame->index;
        } else {
            // A frame is newer than list header and older than list tail, then insert in the middle of the list.
            hIndex = ((PFrame)(pBuf->pFrameList->pHead->data))->index;
            tIndex = ((PFrame)(pBuf->pFrameList->pTail->data))->index;
            if ((pNewFrame->index - hIndex) <= (tIndex - pNewFrame->index)) {
                CHK_STATUS(doubleListGetHeadNode(pBuf->pFrameList, &pCurNode));
                while (pCurNode != NULL) {
                    pNextNode = pCurNode->pNext;
                    pCurFrame = (PFrame) pCurNode->data;
                    pNextFrame = (PFrame) pNextNode->data;
                    if (pCurFrame->index < pNewFrame->index && pNewFrame->index < pNextFrame->index) {
                        doubleListInsertItemAfter(pBuf->pFrameList, pCurNode, (UINT64) pNewFrame);
                        break;
                    }
                    pCurNode = pNextNode;
                }
            } else {
                CHK_STATUS(doubleListGetTailNode(pBuf->pFrameList, &pCurNode));
                while (pCurNode != NULL) {
                    pPrevNode = pCurNode->pPrev;
                    pCurFrame = (PFrame) pCurNode->data;
                    pNextFrame = (PFrame) pPrevNode->data;
                    if (pCurFrame->index > pNewFrame->index && pNewFrame->index > pNextFrame->index) {
                        doubleListInsertItemBefore(pBuf->pFrameList, pCurNode, (UINT64) pNewFrame);
                        break;
                    }
                    pCurNode = pPrevNode;
                }
            }
        }
    } else {
        CHK_STATUS(doubleListInsertItemTail(pBuf->pFrameList, (UINT64)pNewFrame));
    }

    CVAR_SIGNAL(pBuf->cond);

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pBuf->mutex);
    }

    if (retStatus != STATUS_SUCCESS) {
        if (pNewFrame) {
            MEMFREE(pNewFrame);
            pNewFrame = NULL;
        }
    }

    return retStatus;
}

STATUS popFrame(PFrameBuffer pBuf, PFrame *ppFrame)
{
    STATUS retStatus = STATUS_SUCCESS;
    PDoubleListNode pNode = NULL;
    PFrame pNewFrame = NULL;
    UINT32 count = 0;
    BOOL locked = FALSE;

    CHK(ppFrame != NULL && pBuf != NULL && pBuf->pFrameList != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pBuf->mutex);
    locked = TRUE;

    CHK_STATUS(doubleListGetNodeCount(pBuf->pFrameList, &count));
    if (count == 0) {
        CVAR_WAIT(pBuf->cond, pBuf->mutex, INFINITE_TIME_VALUE);
    }

    CHK_STATUS(doubleListGetHeadNode(pBuf->pFrameList, &pNode));
    CHK(pNode != NULL, STATUS_NULL_ARG);
    pNewFrame = (PFrame) pNode->data;
    CHK(pNewFrame != NULL, STATUS_NULL_ARG);
CleanUp:
    if (retStatus == STATUS_SUCCESS) {
        *ppFrame = pNewFrame;
    }
    if (pBuf->recvFlag) {
        pBuf->lastConsumedFrameId = pNewFrame->index;
        pBuf->nextConsumedFrameId = pBuf->lastConsumedFrameId + 1;
    }
    if (locked) {
        MUTEX_UNLOCK(pBuf->mutex);
    }

    return retStatus;
}

STATUS deleteFrame(PFrameBuffer pBuf, PFrame pFrame)
{
    STATUS retStatus = STATUS_SUCCESS;
    PDoubleListNode pNode = NULL;
    BOOL locked = FALSE;

    CHK(pFrame != NULL && pBuf != NULL && pBuf->pFrameList != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pBuf->mutex);
    locked = TRUE;

    CHK_STATUS(doubleListGetHeadNode(pBuf->pFrameList, &pNode));
    CHK(pNode != NULL && pNode->data != NULL, STATUS_NULL_ARG);
    CHK_STATUS(freeFrameData((PFrame)pNode->data));
    CHK_STATUS(doubleListDeleteHead(pBuf->pFrameList));

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pBuf->mutex);
    }

    return retStatus;
}
