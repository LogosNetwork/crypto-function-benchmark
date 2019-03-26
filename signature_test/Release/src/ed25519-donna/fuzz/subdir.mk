################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/ed25519-donna/fuzz/curve25519-ref10.c \
../src/ed25519-donna/fuzz/ed25519-donna-sse2.c \
../src/ed25519-donna/fuzz/ed25519-donna.c \
../src/ed25519-donna/fuzz/ed25519-ref10.c \
../src/ed25519-donna/fuzz/fuzz-curve25519.c \
../src/ed25519-donna/fuzz/fuzz-ed25519.c 

OBJS += \
./src/ed25519-donna/fuzz/curve25519-ref10.o \
./src/ed25519-donna/fuzz/ed25519-donna-sse2.o \
./src/ed25519-donna/fuzz/ed25519-donna.o \
./src/ed25519-donna/fuzz/ed25519-ref10.o \
./src/ed25519-donna/fuzz/fuzz-curve25519.o \
./src/ed25519-donna/fuzz/fuzz-ed25519.o 

C_DEPS += \
./src/ed25519-donna/fuzz/curve25519-ref10.d \
./src/ed25519-donna/fuzz/ed25519-donna-sse2.d \
./src/ed25519-donna/fuzz/ed25519-donna.d \
./src/ed25519-donna/fuzz/ed25519-ref10.d \
./src/ed25519-donna/fuzz/fuzz-curve25519.d \
./src/ed25519-donna/fuzz/fuzz-ed25519.d 


# Each subdirectory must supply rules for building sources it contributes
src/ed25519-donna/fuzz/%.o: ../src/ed25519-donna/fuzz/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


