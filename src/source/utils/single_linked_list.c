/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
/******************************************************************************
 * HEADERS
 ******************************************************************************/
#include "kvs/common_defs.h"
#include "kvs/error.h"
#include "kvs/platform_utils.h"
#include "single_linked_list.h"

/******************************************************************************
 * DEFINITIONS
 ******************************************************************************/

/******************************************************************************
 * FUNCTIONS
 ******************************************************************************/
STATUS priv_single_list_allocateNode(UINT64, PSingleListNode*);
STATUS priv_single_list_insertNodeHead(PSingleList, PSingleListNode);
STATUS priv_single_list_insertNodeTail(PSingleList, PSingleListNode);
STATUS priv_single_list_insertNodeAfter(PSingleList, PSingleListNode, PSingleListNode);
STATUS priv_single_list_getNodeAt(PSingleList, UINT32, PSingleListNode*);

/**
 * Create a new single linked list
 */
STATUS single_list_create(PSingleList* ppList)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSingleList pList = NULL;

    CHK(ppList != NULL, STATUS_NULL_ARG);

    // Allocate the main structure
    pList = (PSingleList) MEMCALLOC(1, SIZEOF(SingleList));
    CHK(pList != NULL, STATUS_NOT_ENOUGH_MEMORY);

    // The list contents are automatically set to 0s by calloc. Just assign and return
    *ppList = pList;

CleanUp:

    return retStatus;
}

STATUS single_list_free(PSingleList pList)
{
    STATUS retStatus = STATUS_SUCCESS;

    // The call is idempotent so we shouldn't fail
    CHK(pList != NULL, retStatus);

    // We shouldn't fail here even if clear fails
    single_list_clear(pList, FALSE);

    // Free the structure itself
    MEMFREE(pList);

CleanUp:

    return retStatus;
}

STATUS single_list_clear(PSingleList pList, BOOL freeData)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSingleListNode pCurNode = NULL;
    PSingleListNode pNextNode = NULL;

    CHK(pList != NULL, STATUS_NULL_ARG);

    // Iterate through and free individual items without re-linking - faster
    pCurNode = pList->pHead;
    while (pCurNode != NULL) {
        pNextNode = pCurNode->pNext;
        if (freeData && ((PVOID) pCurNode->data != NULL)) {
            MEMFREE((PVOID) pCurNode->data);
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

/**
 * Insert a node in the head position in the list
 */
STATUS singleListInsertNodeHead(PSingleList pList, PSingleListNode pNode)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pList != NULL && pNode != NULL, STATUS_NULL_ARG);
    CHK_STATUS(priv_single_list_insertNodeHead(pList, pNode));

CleanUp:

    return retStatus;
}

/**
 * Insert a new node with the data at the head position in the list
 */
STATUS singleListInsertItemHead(PSingleList pList, UINT64 data)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSingleListNode pNode;

    CHK(pList != NULL, STATUS_NULL_ARG);

    // Allocate the node and insert
    CHK_STATUS(priv_single_list_allocateNode(data, &pNode));
    CHK_STATUS(priv_single_list_insertNodeHead(pList, pNode));

CleanUp:

    return retStatus;
}

/**
 * Insert a node in the tail position in the list
 */
STATUS singleListInsertNodeTail(PSingleList pList, PSingleListNode pNode)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pList != NULL && pNode != NULL, STATUS_NULL_ARG);
    CHK_STATUS(priv_single_list_insertNodeTail(pList, pNode));

CleanUp:

    return retStatus;
}

/**
 * Insert a new node with the data at the tail position in the list
 */
STATUS single_list_insertItemTail(PSingleList pList, UINT64 data)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSingleListNode pNode;

    CHK(pList != NULL, STATUS_NULL_ARG);

    // Allocate the node and insert
    CHK_STATUS(priv_single_list_allocateNode(data, &pNode));
    CHK_STATUS(priv_single_list_insertNodeTail(pList, pNode));

CleanUp:

    return retStatus;
}

/**
 * Insert a node after a given node
 */
STATUS singleListInsertNodeAfter(PSingleList pList, PSingleListNode pNode, PSingleListNode pInsertNode)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pList != NULL && pNode != NULL && pInsertNode != NULL, STATUS_NULL_ARG);
    CHK_STATUS(priv_single_list_insertNodeAfter(pList, pNode, pInsertNode));

CleanUp:

    return retStatus;
}

/**
 * Insert a new node with the data after a given node
 */
STATUS singleListInsertItemAfter(PSingleList pList, PSingleListNode pNode, UINT64 data)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSingleListNode pInsertNode;

    CHK(pList != NULL && pNode != NULL, STATUS_NULL_ARG);

    // Allocate the node and insert
    CHK_STATUS(priv_single_list_allocateNode(data, &pInsertNode));
    CHK_STATUS(priv_single_list_insertNodeAfter(pList, pNode, pInsertNode));

CleanUp:

    return retStatus;
}

/**
 * Removes and deletes the head
 */
STATUS single_list_deleteHead(PSingleList pList)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSingleListNode pNode;

    CHK(pList != NULL, STATUS_NULL_ARG);

    // Check if we need to do anything
    CHK(pList->pHead != NULL, retStatus);

    pNode = pList->pHead;
    pList->pHead = pList->pHead->pNext;

    // Null the tail if we have null head
    if (pList->pHead == NULL) {
        pList->pTail = NULL;
    }

    // Decrement the count
    pList->count--;

    // Delete the node
    MEMFREE(pNode);

CleanUp:

    return retStatus;
}

/**
 * Removes and deletes the next node of the specified node
 */
STATUS single_list_deleteNextNode(PSingleList pList, PSingleListNode pNode)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSingleListNode pNextNode;

    CHK(pList != NULL && pNode != NULL, STATUS_NULL_ARG);
    if (pNode->pNext != NULL) {
        pNextNode = pNode->pNext;

        // Fix-up the node
        pNode->pNext = pNextNode->pNext;

        // Fix-up the tail
        if (pNextNode->pNext == NULL) {
            // In this case the tail should point to pNextNode
            CHK(pList->pTail == pNextNode, STATUS_INTERNAL_ERROR);
            pList->pTail = pNode;
        }

        // Decrement the count
        pList->count--;

        // Delete the node
        MEMFREE(pNextNode);
    } else {
        // Validate that it's the tail
        CHK(pList->pTail == pNode, STATUS_INVALID_ARG);
    }

CleanUp:

    return retStatus;
}

/**
 * Removes and deletes the specified node
 */
STATUS single_list_deleteNode(PSingleList pList, PSingleListNode pNode)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSingleListNode pPrevNode = NULL;
    BOOL found = FALSE;

    CHK(pList != NULL && pNode != NULL, STATUS_NULL_ARG);

    if (pList->pHead == pNode) {
        // Fast path to remove the head and return
        CHK_STATUS(single_list_deleteHead(pList));
        CHK(FALSE, retStatus);
    }

    pPrevNode = pList->pHead;
    while (pPrevNode != NULL && !found) {
        if (pPrevNode->pNext == pNode) {
            found = TRUE;
        } else {
            pPrevNode = pPrevNode->pNext;
        }
    }

    if (found) {
        CHK_STATUS(single_list_deleteNextNode(pList, pPrevNode));
    }

CleanUp:

    return retStatus;
}

/**
 * Gets the head node
 */
STATUS single_list_getHeadNode(PSingleList pList, PSingleListNode* ppNode)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pList != NULL && ppNode != NULL, STATUS_NULL_ARG);
    *ppNode = pList->pHead;

CleanUp:

    return retStatus;
}

/**
 * Gets the tail node
 */
STATUS singleListGetTailNode(PSingleList pList, PSingleListNode* ppNode)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pList != NULL && ppNode != NULL, STATUS_NULL_ARG);
    *ppNode = pList->pTail;

CleanUp:

    return retStatus;
}

/**
 * Gets the node at the specified index
 */
STATUS single_list_getNodeAt(PSingleList pList, UINT32 index, PSingleListNode* ppNode)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pList != NULL && ppNode != NULL, STATUS_NULL_ARG);
    CHK(index < pList->count, STATUS_INVALID_ARG);

    CHK_STATUS(priv_single_list_getNodeAt(pList, index, ppNode));

CleanUp:

    return retStatus;
}

/**
 * Gets the node data at the specified index
 */
STATUS singleListGetNodeDataAt(PSingleList pList, UINT32 index, PUINT64 pData)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSingleListNode pNode = NULL;

    CHK(pList != NULL && pData != NULL, STATUS_NULL_ARG);
    CHK(index < pList->count, STATUS_INVALID_ARG);

    CHK_STATUS(priv_single_list_getNodeAt(pList, index, &pNode));
    *pData = pNode->data;

CleanUp:

    return retStatus;
}

/**
 * Gets the node data
 */
STATUS single_list_getNodeData(PSingleListNode pNode, PUINT64 pData)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pNode != NULL && pData != NULL, STATUS_NULL_ARG);
    *pData = pNode->data;

CleanUp:

    return retStatus;
}

/**
 * Gets the next node
 */
STATUS singleListGetNextNode(PSingleListNode pNode, PSingleListNode* ppNode)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pNode != NULL && ppNode != NULL, STATUS_NULL_ARG);
    *ppNode = pNode->pNext;

CleanUp:

    return retStatus;
}

/**
 * Gets the count of nodes in the list
 */
STATUS single_list_getNodeCount(PSingleList pList, PUINT32 pCount)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pList != NULL && pCount != NULL, STATUS_NULL_ARG);
    *pCount = pList->count;

CleanUp:

    return retStatus;
}

/////////////////////////////////////////////////////////////////////////////////
// Internal operations
/////////////////////////////////////////////////////////////////////////////////
STATUS priv_single_list_allocateNode(UINT64 data, PSingleListNode* ppNode)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSingleListNode pNode = (PSingleListNode) MEMCALLOC(1, SIZEOF(SingleListNode));
    CHK(pNode != NULL, STATUS_NOT_ENOUGH_MEMORY);

    pNode->data = data;
    *ppNode = pNode;

CleanUp:

    return retStatus;
}

STATUS priv_single_list_insertNodeHead(PSingleList pList, PSingleListNode pNode)
{
    STATUS retStatus = STATUS_SUCCESS;

    // Fix-up the node
    pNode->pNext = pList->pHead;

    // Fix-up the tail node
    if (pList->pHead == NULL) {
        // In this case the tail should be NULL as well
        CHK(pList->pTail == NULL, STATUS_INTERNAL_ERROR);

        // Fix-up the tail
        pList->pTail = pNode;
    }

    // Fix-up the head
    pList->pHead = pNode;

    // Increment the count
    pList->count++;

CleanUp:

    return retStatus;
}

STATUS priv_single_list_insertNodeTail(PSingleList pList, PSingleListNode pNode)
{
    STATUS retStatus = STATUS_SUCCESS;

    // Fix-up the node
    pNode->pNext = NULL;

    // Fix-up the tail node
    if (pList->pTail != NULL) {
        pList->pTail->pNext = pNode;
    } else {
        // In this case the head should be NULL as well
        CHK(pList->pHead == NULL, STATUS_INTERNAL_ERROR);

        // Fix-up the head
        pList->pHead = pNode;
    }

    // Fix-up the tail
    pList->pTail = pNode;

    // Increment the count
    pList->count++;

CleanUp:

    return retStatus;
}

STATUS priv_single_list_insertNodeAfter(PSingleList pList, PSingleListNode pNode, PSingleListNode pInsertNode)
{
    STATUS retStatus = STATUS_SUCCESS;

    // Fix-up the insert node
    pInsertNode->pNext = pNode->pNext;

    // Fix-up the tail
    if (pNode->pNext == NULL) {
        // In this case we should have the tail pointing to pNode
        CHK(pList->pTail == pNode, STATUS_INTERNAL_ERROR);

        // Fix-up the tail
        pList->pTail = pInsertNode;
    }

    // Fix-up the current node next
    pNode->pNext = pInsertNode;

    // Increment the count
    pList->count++;

CleanUp:

    return retStatus;
}

STATUS priv_single_list_getNodeAt(PSingleList pList, UINT32 index, PSingleListNode* ppNode)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSingleListNode pNode = pList->pHead;
    UINT32 i;

    for (i = 0; i < index; i++) {
        // We shouldn't have NULL unless the list is corrupted
        CHK(pNode != NULL, STATUS_INTERNAL_ERROR);
        pNode = pNode->pNext;
    }

    *ppNode = pNode;

CleanUp:

    return retStatus;
}

STATUS singleListAppendList(PSingleList pDstList, PSingleList* ppListToAppend)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(ppListToAppend != NULL && ppListToAppend != NULL, STATUS_NULL_ARG);
    PSingleList pListToAppend = *ppListToAppend;

    CHK(pListToAppend != NULL, retStatus);

    if (pDstList->count == 0) {
        pDstList->pHead = pListToAppend->pHead;
        pDstList->pTail = pListToAppend->pTail;
    } else if (pListToAppend->count != 0) {
        pDstList->pTail->pNext = pListToAppend->pHead;
        pDstList->pTail = pListToAppend->pTail;
    }

    pDstList->count += pListToAppend->count;
    MEMFREE(pListToAppend);
    *ppListToAppend = NULL;
CleanUp:

    return retStatus;
}
