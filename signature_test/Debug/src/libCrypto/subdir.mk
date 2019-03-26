################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/libCrypto/MultiSig.cpp \
../src/libCrypto/Schnorr.cpp 

OBJS += \
./src/libCrypto/MultiSig.o \
./src/libCrypto/Schnorr.o 

CPP_DEPS += \
./src/libCrypto/MultiSig.d \
./src/libCrypto/Schnorr.d 


# Each subdirectory must supply rules for building sources it contributes
src/libCrypto/%.o: ../src/libCrypto/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I"/home/peng/workspace_openssl/signature_test/src" -O0 -g3 -Wall -c -fmessage-length=0 -std=c++17 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


