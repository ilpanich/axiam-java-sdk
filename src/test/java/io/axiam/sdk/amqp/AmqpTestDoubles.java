package io.axiam.sdk.amqp;

import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Delivery;
import com.rabbitmq.client.Envelope;

import org.slf4j.Logger;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.List;

/** Broker-free doubles shared by the AMQP tests that need a recording channel and logger. */
final class AmqpTestDoubles {

    private AmqpTestDoubles() {
    }

    /** One recorded {@code basicAck}/{@code basicNack}. */
    record AckNack(String type, long deliveryTag, boolean multiple, boolean requeue) {
    }

    static Delivery delivery(long deliveryTag, byte[] body) {
        Envelope envelope = new Envelope(deliveryTag, false, "axiam.authz.request", "authz.request");
        return new Delivery(envelope, new AMQP.BasicProperties.Builder().build(), body);
    }

    /** A {@link Channel} that records acks and nacks and answers every other call with a default. */
    static Channel recordingChannel(List<AckNack> calls) {
        InvocationHandler handler = (proxy, method, args) -> {
            switch (method.getName()) {
                case "basicAck":
                    calls.add(new AckNack("ack", (long) args[0], (boolean) args[1], false));
                    return null;
                case "basicNack":
                    calls.add(new AckNack("nack", (long) args[0], (boolean) args[1], (boolean) args[2]));
                    return null;
                case "toString":
                    return "recordingChannel";
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                default:
                    return defaultReturnValue(method.getReturnType());
            }
        };
        return (Channel) Proxy.newProxyInstance(
                Channel.class.getClassLoader(), new Class<?>[] {Channel.class}, handler);
    }

    /** A {@link Logger} that records every {@code warn} message, formatted. */
    static Logger recordingLogger(List<String> warnings) {
        InvocationHandler handler = (proxy, method, args) -> {
            if ("warn".equals(method.getName()) && args != null && args.length > 0 && args[0] instanceof String) {
                warnings.add(format(args));
                return null;
            }
            switch (method.getName()) {
                case "toString":
                case "getName":
                    return "recordingLogger";
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                default:
                    return defaultReturnValue(method.getReturnType());
            }
        };
        return (Logger) Proxy.newProxyInstance(
                Logger.class.getClassLoader(), new Class<?>[] {Logger.class}, handler);
    }

    private static String format(Object[] invocationArgs) {
        String pattern = (String) invocationArgs[0];
        Object[] values;
        if (invocationArgs.length == 2 && invocationArgs[1] instanceof Object[]) {
            values = (Object[]) invocationArgs[1];
        } else {
            values = java.util.Arrays.copyOfRange(invocationArgs, 1, invocationArgs.length);
        }
        StringBuilder sb = new StringBuilder();
        int next = 0;
        int i = 0;
        while (i < pattern.length()) {
            if (i + 1 < pattern.length() && pattern.charAt(i) == '{' && pattern.charAt(i + 1) == '}') {
                sb.append(next < values.length ? String.valueOf(values[next++]) : "{}");
                i += 2;
            } else {
                sb.append(pattern.charAt(i));
                i++;
            }
        }
        return sb.toString();
    }

    private static Object defaultReturnValue(Class<?> returnType) {
        if (!returnType.isPrimitive()) {
            return null;
        }
        if (returnType == boolean.class) {
            return true;
        }
        if (returnType == void.class) {
            return null;
        }
        return 0;
    }
}
