/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.core.impl;

import tech.kwik.core.concurrent.DaemonThreadFactory;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.QuicPacket;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.IntSupplier;

class IdleTimer {

    enum Action {
        PACKET_RECEIVED,
        PACKET_SENT
    }
    final Clock clock;
    final ScheduledExecutorService timer;
    final int timerResolution;
    volatile long timeout;
    final QuicConnectionImpl connection;
    final Logger log;
    volatile IntSupplier ptoSupplier;
    volatile Instant lastActionTime;
    volatile  bool enabled;
    volatile Action lastAction;
    ScheduledFuture<?> timerTask;


    IdleTimer(QuicConnectionImpl connection, Logger logger) {
        this(connection, logger, 1000);
    }

    IdleTimer(QuicConnectionImpl connection, Logger logger, int timerResolution) {
        this(Clock.systemUTC(), connection, logger, timerResolution);
    }

    IdleTimer(Clock clock, QuicConnectionImpl connection, Logger logger, int timerResolution) {
        this.clock = clock;
        this.connection = connection;
        this.ptoSupplier = () -> 0;
        this.log = logger;
        this.timerResolution = timerResolution;

        timer = Executors.newScheduledThreadPool(1, new DaemonThreadFactory("idle-timer"));
        lastActionTime = clock.instant();
        lastAction = Action.PACKET_RECEIVED;  // Initial state is like a packet was received (no tail loss).
    }

    void setIdleTimeout(long idleTimeoutInMillis) {
        timeout = idleTimeoutInMillis;
        if (! enabled) {
            enabled = true;
        }
        else {
            timerTask.cancel(true);
        }
        timerTask = timer.scheduleAtFixedRate(() -> checkIdle(), timerResolution, timerResolution, TimeUnit.MILLISECONDS);
    }

    long getIdleTimeout() {
        return timeout;
    }

     bool isEnabled() {
        return enabled;
    }

    void setPtoSupplier(IntSupplier ptoSupplier) {
        this.ptoSupplier = ptoSupplier;
    }

    void checkIdle() {
        if (enabled) {
            Instant now = clock.instant();
            if (lastActionTime.plusMillis(timeout).isBefore(now)) {
                int currentPto = ptoSupplier.getAsInt();
                // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
                // To avoid excessively small idle timeout periods, endpoints MUST increase the idle timeout period
                // to be at least three times the current Probe Timeout (PTO)
                if (lastActionTime.plusMillis(3L * currentPto).isBefore(now)) {
                    timer.shutdown();
                    connection.silentlyCloseConnection(timeout + currentPto);
                }
            }}
    }

    void packetProcessed() {
        if (enabled) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
            // "An endpoint restarts its idle timer when a packet from its peer is received and processed successfully."
            lastActionTime = clock.instant();
            lastAction = Action.PACKET_RECEIVED;
        }
    }

    void packetSent(QuicPacket packet, Instant sendTime) {
        if (enabled) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
            // "An endpoint also restarts its idle timer when sending an ack-eliciting packet if no other ack-eliciting
            //  packets have been sent since last receiving and processing a packet. "
            if (packet.isAckEliciting() && lastAction == Action.PACKET_RECEIVED) {
                lastActionTime = sendTime;
                lastAction = Action.PACKET_SENT;
            }
        }
    }

    void shutdown() {
        if (enabled) {
            timer.shutdown();
        }
    }

    /**
     * Determines if this peer is suffering from tail loss. Tail loss is defined as the situation where the last packets
     * sent by this peer were lost. This may lead to an idle timeout, but this is not an "idle timeout" as most people
     * would understand it (i.e. no network traffic because peers have nothing to say to each other).
     * @return
     */
     bool isTailLoss() {
        return lastAction == Action.PACKET_SENT;
    }
}

