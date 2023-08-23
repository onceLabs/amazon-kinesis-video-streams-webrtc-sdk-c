当前AWS Webrtc SDK中采用了RTCP的TWCC(Transport-wide Congestion Control)进行网络拥塞估计，但是并未对估计结果进行处理，没有根据当前的网络传输状况，调整音视频发送的速率，也就没有平滑发送模块的相关实现。

# 1. TWCC原理
简单的说所有媒体RTP数据包发送的时候，会在RTP的扩展头中增加一个统一的序列号，可以认为每个数据包有一个唯一的编号，这样所有发出去的数据都有了对应的序列号、发送时刻、包大小三个信息。在接收端收到这些RTP数据包之后，会把每个收到的序列号以及收到的此序列号的接受时刻信息，按照TransportFeedback报文定义的格式封装到RTCP包中，反馈到发送端。发送端根据这些反馈信息，就能估算出当前网络传输的状况，包括丢包、延时、带宽三方面的信息。

## 1. 1. 开启Transport-cc
在SDP（SdpMediaDescription）中需要增加：

```
a=rtcp-fb:96 transport-cc
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
```

## 1. 2. RTP Header扩展
`RTP transport sequence number`报头定义如下：

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       0xBE    |    0xDE       |           length=1            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  ID   | L=1   |transport-wide sequence number | zero padding  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

由于属于RTP报头扩展，所以可以看到以0xBEDE固定字段开头，`transport sequence number`占两个字节，存储在One-Byte Header的Extension data字段。由于按4字节对齐，所以还有值为0的填充数据。对于同一个PeerConnection下的所有包使用同一个计数器，音视频使用同一个序列号递增，这个`transport sequence number`是从1开始递增的。

## 1. 3. TransportFeedback RTCP
接收端通过TransportFeedback RTCP向发送端反馈收到的各个RTP包的到达时间信息。主要收集每个包的丢包和延迟情况，组装`packet chunk`和`recv delta`。

```
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P|  FMT=15 |    PT=205     |           length              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     SSRC of packet sender                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      SSRC of media source                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      base sequence number     |      packet status count      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 reference time                | fb pkt. count |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          packet chunk         |         packet chunk          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   .                                                               .
   .                                                               .
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         packet chunk          |  recv delta   |  recv delta   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   .                                                               .
   .                                                               .
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           recv delta          |  recv delta   | zero padding  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



| 字段                  | 说明                               | 补充                                                         |
| --------------------- | ---------------------------------- | ------------------------------------------------------------ |
| version               | 版本                               | 固定为2                                                      |
| padding               | 填充标识                           | 1位，如设置填充位，在包尾将包含附加填充字，它不属于有效载荷  |
| FMT                   | 反馈消息类型 feedback message type | 固定为15                                                     |
| PT                    | 载荷类型 payload type              | 固定为205  RTPFB                                             |
| SSRC of packet sender | 原始同步源标识                     | 最原始的来源SSRC                                             |
| SSRC of media source  | 媒体源同步源标识                   | 本次反馈的媒体源SSRC                                         |
| base sequence number  | 基础序号                           | 本次反馈的第一个包的序号；也就是RTP扩展头的序列号            |
| packet status count   | 包个数                             | 本次反馈包含多少个包的状态；从基础序号开始算                 |
| reference time        | 基准时间                           | 绝对时间；计算该包中每个媒体包的到达时间都要基于这个基准时间计算 |
| feedback packet count | 反馈包号                           | 本包是第几个transport-cc包，每次加1                          |
| packet chunk          | 包状态块                           | 表示一组包的状态列表；从基础序号开始                         |
| recv delta            | 接收增量                           | 表示一组收到的包的状态；对应“packet chunk”中收到的包         |
```

# 2. SDK中TWCC的实现
**Master：运行Webrtc SDK中的kvsWebrtcClientMaster；**
**Viewer：用浏览器打开Testpage(https://awslabs.github.io/amazon-kinesis-video-streams-webrtc-sdk-js/examples/index.html)，点击Start Viewer。**
**<font class="text-color-01" color="#f44336">当前TWCC的反馈机制只在Browser启动的Viewer上支持。</font>**

下面以视频数据的发送为例，描述TWCC拥塞预估的流程，及Master端的处理逻辑。
![](https://huatu.98youxi.com/markdown/work/uploads/upload_95634b8b439afc922eb03b8def942451.png)

## 2. 1. 数据发送
在sample通过`writeFrame()`发送数据包时，每一个RtpPacket会通过调用以下代码生成扩展字段，

```
twsn = (UINT16) ATOMIC_INCREMENT(&pKvsRtpTransceiver->pKvsPeerConnection->transportWideSequenceNumber);
extpayload = TWCC_PAYLOAD(pKvsRtpTransceiver->pKvsPeerConnection->twccExtId, twsn);
pRtpPacket->header.extensionPayload = (PBYTE) &extpayload;
```

再调用`encryptRtpPacket()`接口将数据组装成RTP包，组装完成的RTP包通过`iceAgentSendPacket()`接口，再逐层调用到`socketSendDataWithRetry()`接口，最后经socket发送到网络。
对于发送成功且已开启Transport-cc的数据包，调用`twccManagerOnPacketSent()`将发送的数据包信息存储到`TwccManager`中，

```
sendStatus = iceAgentSendPacket(pKvsPeerConnection->pIceAgent, rawPacket, packetLen);
if (sendStatus == STATUS_SEND_DATA_FAILED) {
    ......
} else if (sendStatus == STATUS_SUCCESS && pKvsRtpTransceiver->pKvsPeerConnection->twccExtId != 0) {
    pRtpPacket->sentTime = GETTIME();
    twccManagerOnPacketSent(pKvsPeerConnection, pRtpPacket);
}
```

```
STATUS twccManagerOnPacketSent(PKvsPeerConnection pc, PRtpPacket pRtpPacket)
{
    seqNum = TWCC_SEQNUM(pRtpPacket->header.extensionPayload);
    CHK_STATUS(stackQueueEnqueue(&pc->pTwccManager->twccPackets, seqNum));
    pc->pTwccManager->twccPacketBySeqNum[seqNum].seqNum = seqNum;
    pc->pTwccManager->twccPacketBySeqNum[seqNum].packetSize = pRtpPacket->payloadLength;
    pc->pTwccManager->twccPacketBySeqNum[seqNum].localTimeKvs = pRtpPacket->sentTime;
    pc->pTwccManager->twccPacketBySeqNum[seqNum].remoteTimeKvs = TWCC_PACKET_LOST_TIME;
    pc->pTwccManager->lastLocalTimeKvs = pRtpPacket->sentTime;
}
```

存储的内容包括transport sequence number(seqNum)，数据包大小(packetSize)，发送时间戳等信息(localTimeKvs)。

## 2. 2. 数据接收
发送端接收到的RTCP数据包最终会调用`onRtcpPacket()`进行解析及处理，而处理TransportFeedback RTCP类型包的为`onRtcpTwccPacket()`接口。`onRtcpTwccPacket()`中通过调用`parseRtcpTwccPacket()`解析接收端发过来的base sequence number，packet chunk和recv delta。再根据`TwccManager`中存储的数据从而计算出sentBytes, receivedBytes，sentPackets, receivedPackets, duration的值。

```
STATUS onRtcpTwccPacket(PRtcpPacket pRtcpPacket, PKvsPeerConnection pKvsPeerConnection)
{
    twcc = pKvsPeerConnection->pTwccManager;
    CHK_STATUS(parseRtcpTwccPacket(pRtcpPacket, twcc));
    CHK_STATUS(stackQueueIsEmpty(&twcc->twccPackets, &empty));
    CHK(!empty, STATUS_SUCCESS);
    CHK_STATUS(stackQueuePeek(&twcc->twccPackets, &sn));
    ageOfOldestPacket = twcc->lastLocalTimeKvs - twcc->twccPacketBySeqNum[(UINT16) sn].localTimeKvs;
    CHK(ageOfOldestPacket > TWCC_ESTIMATOR_TIME_WINDOW / 2, STATUS_SUCCESS);
    localStartTimeKvs = twcc->twccPacketBySeqNum[(UINT16) (sn - 1)].localTimeKvs;
    if (localStartTimeKvs == TWCC_PACKET_UNITIALIZED_TIME) {
        // time not yet set (only happens for first rtp packet)
        localStartTimeKvs = twcc->twccPacketBySeqNum[(UINT16) sn].localTimeKvs;
    }
    for (seqNum = sn; seqNum != twcc->lastReportedSeqNum; seqNum++) {
        twccPacket = &twcc->twccPacketBySeqNum[seqNum];
        localEndTimeKvs = twccPacket->localTimeKvs;
        duration = localEndTimeKvs - localStartTimeKvs;
        sentBytes += twccPacket->packetSize;
        sentPackets++;
        if (twccPacket->remoteTimeKvs != TWCC_PACKET_LOST_TIME) {
            receivedBytes += twccPacket->packetSize;
            receivedPackets++;
        }
    }
    if (duration > 0) {
        MUTEX_UNLOCK(pKvsPeerConnection->twccLock);
        locked = FALSE;
        pKvsPeerConnection->onSenderBandwidthEstimation(pKvsPeerConnection->onSenderBandwidthEstimationCustomData, sentBytes, receivedBytes,
                                                        sentPackets, receivedPackets, duration);
    }
}
```

最终调用`onSenderBandwidthEstimation()`接口将sentBytes, receivedBytes，sentPackets, receivedPackets, duration反馈给应用层。
`onSenderBandwidthEstimation()`是应用层createSampleStreamingSession时通过`peerConnectionOnSenderBandwidthEstimation()`注册的回调函数`sampleSenderBandwidthEstimationHandler()`。

## 2. 3. 拥塞估计后的处理
以上通过TWCC获得到网路的拥塞情况后，当前SDK中并未做其他处理，`sampleSenderBandwidthEstimationHandler()`只进行了打印操作。

```
VOID sampleSenderBandwidthEstimationHandler(UINT64 customData, UINT32 txBytes, UINT32 rxBytes, UINT32 txPacketsCnt, UINT32 rxPacketsCnt,
                                            UINT64 duration)
{
    UINT32 lostPacketsCnt = txPacketsCnt - rxPacketsCnt;
    UINT32 percentLost = lostPacketsCnt * 100 / txPacketsCnt;
    UINT32 bitrate = 1024;
    if (percentLost < 2) {
        // increase encoder bitrate by 2 percent
        bitrate *= 1.02f;
    } else if (percentLost > 5) {
        // decrease encoder bitrate by packet loss percent
        bitrate *= (1.0f - percentLost / 100.0f);
    }
    // otherwise keep bitrate the same

    DLOGW("received sender bitrate estimation: suggested bitrate %u sent: %u bytes %u packets received: %u bytes %u packets in %lu msec, ", bitrate,
          txBytes, txPacketsCnt, rxBytes, rxPacketsCnt, duration / 10000ULL);
}
```

而SDK的sample中，音视频的发送各创建一个线程，`sendVideoPackets()`和`sendAudioPackets()`，音频发送频率始终是20ms（SAMPLE_AUDIO_FRAME_DURATION）一次，视频发送频率始终是40ms（SAMPLE_VIDEO_FRAME_DURATION）一次。并没有根据拥塞估计的带宽对音视频包的发送速率做调整。

## 2. 4. 对比测试
针对以上问题，做了一个对比测试：一个Master，两个Viewer； 其中一个Viewer跟Master在同一网段，后续我们称作viewer1；一个Viewer在另一个网段，后续我们称作viewer2。

想得到sampleSenderBandwidthEstimationHandler接口的打印，我们需要修改一下打印：

```
diff --git a/samples/Common.c b/samples/Common.c
index 3e769cf4f..7a3ad1ca2 100755
--- a/samples/Common.c
+++ b/samples/Common.c
@@ -686,6 +686,7 @@ STATUS createSampleStreamingSession(PSampleConfiguration pSampleConfiguration, P
     CHK_STATUS(transceiverOnBandwidthEstimation(pSampleStreamingSession->pAudioRtcRtpTransceiver, (UINT64) pSampleStreamingSession,
                                                 sampleBandwidthEstimationHandler));
     // twcc bandwidth estimation
+    DLOGW("create session: %p", pSampleStreamingSession);
     CHK_STATUS(peerConnectionOnSenderBandwidthEstimation(pSampleStreamingSession->pPeerConnection, (UINT64) pSampleStreamingSession,
                                                          sampleSenderBandwidthEstimationHandler));
     pSampleStreamingSession->startUpLatency = 0;
@@ -855,7 +856,8 @@ VOID sampleSenderBandwidthEstimationHandler(UINT64 customData, UINT32 txBytes, U
     }
     // otherwise keep bitrate the same

-    DLOGS("received sender bitrate estimation: suggested bitrate %u sent: %u bytes %u packets received: %u bytes %u packets in %lu msec, ", bitrate,
+    PSampleStreamingSession pSampleStreamingSession = (PSampleStreamingSession)customData;
+    DLOGW("%p received sender bitrate estimation: suggested bitrate %u sent: %u bytes %u packets received: %u bytes %u packets in %lu msec, ", pSampleStreamingSession, bitrate,
           txBytes, txPacketsCnt, rxBytes, rxPacketsCnt, duration / 10000ULL);
 }
```

为了区分两个Viewer，我们在createSampleStreamingSession中打出每个session的指针，另外因为DLOGS需要log level为LOG_LEVEL_VERBOSE且LOG_STREAMING宏定义的前提下，因此我们暂时将DLOGS替换为DLOGW来打印。

两个Viewer同时连接会启动两个Session，viewer1的指针为0x7fe444000b20，viewer2的指针为0x7fe45c006a20，我们抓到的log如下：

![](https://huatu.98youxi.com/markdown/work/uploads/upload_1ab5c0802b2bf67fb2e4c95af73516ed.png)

按照上面接口中的处理，通过接收包和发送包会计算出建议的码率，即log中的suggested bitrate关键字，我们对比两个Viewer的建议码率得到以下曲线：

![](https://huatu.98youxi.com/markdown/work/uploads/upload_821b25ace2f05f0bdbde49f1f6f77c21.png)

从这个曲线图，我们可以看到同一网段的Viewer，网络较稳定，建议码率也较稳定，也就是发送的包和收到的包基本是稳定的，较少丢包；而跨网段的Viewer，建议码率却抖动厉害，也就是在同样的发送包数的情况下，接收包数明显少，丢包较严重。
