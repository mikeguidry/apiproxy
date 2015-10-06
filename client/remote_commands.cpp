#include <windows.h>
#include "../commands.h"
#include "../structures.h"
#include "../memverify.h"
#include "client_structures.h"
#include "customheap.h"

#include "remote_commands.h"

// remove from global.. so we can support multiple connections later.. or channels amongst same
extern int proxy_sock;

// copy all shadow memory to the remote side
int PushData(DWORD_PTR start, DWORD_PTR size) {
	int r = 0;
	DWORD_PTR ret = 0;
	int count = size;
	int split = (1024 * 1024 * 8);
	int left = size;
	int sending = 0;
	int sent = 0;
	int s = 0;
	char *ptr = NULL;

	if (size <= 0) return 0;

	//OutputDebugString("pushing partial packet of data\r\n");

	//split
	int pkt_len = sizeof(ZmqHdr) + sizeof(ZmqPkt) + sizeof(MemTransfer) + split;
	if ((ptr = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pkt_len + 1)) == NULL) {
		return -1;
	}
	ZmqHdr *hdr = (ZmqHdr *)(ptr);
	ZmqPkt *pkt = (ZmqPkt *)((char *)ptr + sizeof(ZmqHdr));
	MemTransfer *minfo = (MemTransfer *)((char *)ptr + sizeof(ZmqHdr) + sizeof(ZmqPkt));
	char ebuf[1024];
	
	while (left > 0) {
		
		sending = min(split, left);
		
		hdr->len = sizeof(ZmqPkt) + sizeof(MemTransfer) + sending;
		pkt->len = sizeof(ZmqPkt) + sizeof(MemTransfer) + sending;
		
		hdr->type = MEM_PUSH;
		pkt->cmd = MEM_PUSH;
		minfo->cmd = MEM_PUSH;
		
		
		// memory information required to allocate remotely..
		minfo->addr = (void *)((DWORD_PTR)start + sent);
		minfo->len = sending;
		char *dst = (char *)(ptr + sizeof(ZmqHdr) + sizeof(ZmqPkt) + sizeof(MemTransfer));
		char *src = (char *)(start + sent);
		
		//wsprintf(ebuf, "src %p dst %p size %d\r\n", src, dst, sending);
		//OutputDebugString(ebuf);
		//CopyMemory((void *)dst, (void *)src, sending-1);
		for (int a = 0; a < sending; a++) {
			dst[a] = src[a];
		}
		
		//wsprintf(ebuf, "MEM PUSH size %d sent %d left %d count %d split %d - sending %d @%p\r\n", size, sent, left, count, split, sending, minfo->addr);
		//OutputDebugString(ebuf);
		
		if ((s = send(proxy_sock, ptr, hdr->len + sizeof(ZmqHdr), 0)) < pkt->len) {
			// we need some global fatal variables..
			return -1;
		}
		
		if ((r = recv(proxy_sock, ptr, pkt_len, 0)) < sizeof(ZmqRet)) {
			// we need some global fatal variables..
			return -1;
		}
		
		ZmqRet *retpkt = (ZmqRet *)ptr;
		if (retpkt->response == 1) {
			//OutputDebugString("MEM PUSH OK\r\n");
			//__asm int 3
			//ExitProcess(0);
			sent += sending;
			left -= sending;
		}
		else {
			
			wsprintf(ebuf, "MEM PUSH FAIL addr %p", start + sent);
			__asm int 3
				break;
			
			
		}
	}
	
	if (sent == size) {
		ret = 1;
	}
	
	return ret;
}

// copy all shadow memory to the remote side
int PushRegion(ShadowRegion *shdw) {
	int r = 0;
	DWORD_PTR ret = 0;
	int size = shdw->size;
	int count = size;
	int split = (1024 * 1024 * 8);
	int left = size;
	int sending = 0;
	int sent = 0;
	int s = 0;
	char *ptr = NULL;
	char *start = (char *)shdw->address;
																			//split
	int pkt_len = sizeof(ZmqHdr) + sizeof(ZmqPkt) + sizeof(MemTransfer) + split;
	if ((ptr = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pkt_len + 1)) == NULL) {
		return -1;
	}
	ZmqHdr *hdr = (ZmqHdr *)(ptr);
	ZmqPkt *pkt = (ZmqPkt *)((char *)ptr + sizeof(ZmqHdr));
	MemTransfer *minfo = (MemTransfer *)((char *)ptr + sizeof(ZmqHdr) + sizeof(ZmqPkt));
	char ebuf[1024];

	while (left > 0) {

		sending = min(split, left);

		hdr->len = sizeof(ZmqPkt) + sizeof(MemTransfer) + sending;
		pkt->len = sizeof(ZmqPkt) + sizeof(MemTransfer) + sending;

		hdr->type = MEM_PUSH;
		pkt->cmd = MEM_PUSH;
		minfo->cmd = MEM_PUSH;

		
		// memory information required to allocate remotely..
		minfo->addr = (void *)((DWORD_PTR)start + sent);
		minfo->len = sending;
		char *dst = (char *)(ptr + sizeof(ZmqHdr) + sizeof(ZmqPkt) + sizeof(MemTransfer));
		char *src = (char *)(start + sent);

		//wsprintf(ebuf, "src %p dst %p size %d\r\n", src, dst, sending);
		//OutputDebugString(ebuf);
		//CopyMemory((void *)dst, (void *)src, sending-1);
		for (int a = 0; a < sending; a++) {
			dst[a] = src[a];
		}

		//wsprintf(ebuf, "MEM PUSH size %d sent %d left %d count %d split %d - sending %d @%p\r\n", size, sent, left, count, split, sending, minfo->addr);
		//OutputDebugString(ebuf);

		if ((s = send(proxy_sock, ptr, hdr->len + sizeof(ZmqHdr), 0)) < pkt->len) {
			// we need some global fatal variables..
			return -1;
		}

		if ((r = recv(proxy_sock, ptr, pkt_len, 0)) < sizeof(ZmqRet)) {
			// we need some global fatal variables..
			return -1;
		}

		ZmqRet *retpkt = (ZmqRet *)ptr;
		if (retpkt->response == 1) {
			//OutputDebugString("MEM PUSH OK\r\n");
			//__asm int 3
			//ExitProcess(0);
			sent += sending;
			left -= sending;
		}
		else {
			
			wsprintf(ebuf, "MEM PUSH FAIL addr %p", start + sent);
			__asm int 3
			break;

			
		}
	}

	if (sent == size) {
		shdw->pushed = 1;
		ret = 1;
		shdw->LastSync = CRC_Region(shdw->address, shdw->size);
	}

	return ret;
}

// copy all shadow memory to the remote side
int PullRegion(DWORD_PTR start, DWORD_PTR size) {
	int r = 0;
	DWORD_PTR ret = 0;
	int count = size;
	int split = (1024 * 1024 * 8);
	int left = size;
	int sending = 0;
	int sent = 0;
	int s = 0;
	char *ptr = NULL;

	int pkt_len = sizeof(ZmqHdr) + sizeof(ZmqPkt) + sizeof(MemTransfer) + split;

	if ((ptr = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pkt_len + 1)) == NULL) {
		return -1;
	}

	ZmqHdr *hdr = (ZmqHdr *)(ptr);
	ZmqPkt *pkt = (ZmqPkt *)((char *)ptr + sizeof(ZmqHdr));
	MemTransfer *minfo = (MemTransfer *)((char *)ptr + sizeof(ZmqHdr) + sizeof(ZmqPkt));
	char ebuf[1024];

	while (left > 0) {

		sending = min(split, left);

		hdr->len = sizeof(ZmqPkt) + sizeof(MemTransfer);
		pkt->len = sizeof(ZmqPkt) + sizeof(MemTransfer);

		hdr->type = MEM_PEEK;
		pkt->cmd = MEM_PEEK;
		minfo->cmd = MEM_PEEK;

		
		// memory information required to allocate remotely..
		minfo->addr = (void *)((DWORD_PTR)start + sent);
		minfo->len = sending;
		//char *dst = (char *)(ptr + sizeof(ZmqHdr) + sizeof(ZmqPkt) + sizeof(MemTransfer));
		//char *src = (char *)(start + sent);

		//wsprintf(ebuf, "src %p dst %p size %d\r\n", src, dst, sending);
		//OutputDebugString(ebuf);
		//CopyMemory((void *)dst, (void *)src, sending-1);
		//for (int a = 0; a < sending; a++) {dst[a] = src[a];}

		//wsprintf(ebuf, "MEM PUSH size %d sent %d left %d count %d split %d - sending %d @%p\r\n", size, sent, left, count, split, sending, minfo->addr);
		//OutputDebugString(ebuf);

		if ((s = send(proxy_sock, ptr, hdr->len + sizeof(ZmqHdr), 0)) < pkt->len) {
			// we need some global fatal variables..
			return -1;
		}

		if ((r = recv(proxy_sock, ptr, pkt_len, 0)) < sizeof(ZmqRet)) {
			// we need some global fatal variables..
			return -1;
		}

		ZmqRet *retpkt = (ZmqRet *)ptr;
		if (retpkt->response == 1) {

			char *rdata = (char *)((char *)ptr + sizeof(ZmqRet));
			CopyMemory((void *)((char *)start + sent), rdata, sending);

			wsprintf(ebuf, "MEM PEEK addr %p size %d\r\n", start+sent, sending);
			OutputDebugString(ebuf);
			//__asm int 3
			//ExitProcess(0);
			sent += sending;
			left -= sending;
		}
		else {
			
			wsprintf(ebuf, "MEM PEAK FAIL addr %p", start + sent);
			__asm int 3
			break;

			
		}
	}

	if (sent == size) ret = 1;

	return ret;
}
