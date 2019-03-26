################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/ed25519-donna/ed25519.c 

O_SRCS += \
../src/ed25519-donna/ed25519.o 

OBJS += \
./src/ed25519-donna/ed25519.o 

C_DEPS += \
./src/ed25519-donna/ed25519.d 


# Each subdirectory must supply rules for building sources it contributes
src/ed25519-donna/%.o: ../src/ed25519-donna/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


