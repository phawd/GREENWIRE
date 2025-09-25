#!/usr/bin/env sh

APP_HOME=$(cd "$(dirname "$0")"; pwd -P)
CLASSPATH="$APP_HOME/gradle/wrapper/gradle-wrapper.jar"
DEFAULT_JVM_OPTS=""
exec "$JAVA_HOME/bin/java" $DEFAULT_JVM_OPTS -classpath "$CLASSPATH" org.gradle.wrapper.GradleWrapperMain "$@"