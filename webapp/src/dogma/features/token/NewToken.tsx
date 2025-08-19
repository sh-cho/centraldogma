import {
  Button,
  Checkbox,
  Flex,
  FormControl,
  FormErrorMessage,
  FormHelperText,
  FormLabel,
  Input,
  Popover,
  PopoverArrow,
  PopoverBody,
  PopoverCloseButton,
  PopoverContent,
  PopoverFooter,
  PopoverHeader,
  PopoverTrigger,
  Spacer,
  useDisclosure,
  VStack,
} from '@chakra-ui/react';
import { SerializedError } from '@reduxjs/toolkit';
import { FetchBaseQueryError } from '@reduxjs/toolkit/query';
import { DisplaySecretModal } from 'dogma/features/token/DisplaySecretModal';
import { IpAccessControlRule } from 'dogma/features/token/TokenDto';
import IpAccessControlForm from 'dogma/features/token/IpAccessControlForm';
import { useAddNewTokenMutation } from 'dogma/features/api/apiSlice';
import { newNotification } from 'dogma/features/notification/notificationSlice';
import ErrorMessageParser from 'dogma/features/services/ErrorMessageParser';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { IoMdArrowDropdown } from 'react-icons/io';
import { useAppDispatch, useAppSelector } from 'dogma/hooks';

const APP_ID_PATTERN = /^[0-9A-Za-z](?:[-+_0-9A-Za-z\.]*[0-9A-Za-z])?$/;

type FormData = {
  appId: string;
  isSystemAdmin: boolean;
};

export const NewToken = () => {
  const {
    isOpen: isNewTokenFormOpen,
    onToggle: onNewTokenFormToggle,
    onClose: onNewTokenFormClose,
  } = useDisclosure();
  const {
    isOpen: isSecretModalOpen,
    onToggle: onSecretModalToggle,
    onClose: onSecretModalClose,
  } = useDisclosure();
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<FormData>();
  const [addNewToken, { isLoading }] = useAddNewTokenMutation();
  const [tokenDetail, setTokenDetail] = useState(null);
  const [ipAccessControlRules, setIpAccessControlRules] = useState<IpAccessControlRule[]>([]);
  const dispatch = useAppDispatch();
  const { user } = useAppSelector((state) => state.auth);
  const onSubmit = async (formData: FormData) => {
    const tokenData = {
      appId: formData.appId,
      isSystemAdmin: formData.isSystemAdmin || false,
      ipAccessControlRules: ipAccessControlRules.length > 0 ? ipAccessControlRules : undefined,
    };

    const data = new URLSearchParams();
    data.append('appId', tokenData.appId);
    data.append('isSystemAdmin', tokenData.isSystemAdmin.toString());
    if (tokenData.ipAccessControlRules) {
      data.append('ipAccessControlRules', JSON.stringify(tokenData.ipAccessControlRules));
    }

    try {
      const response = await addNewToken({ data: data.toString() }).unwrap();
      if ((response as { error: FetchBaseQueryError | SerializedError }).error) {
        throw (response as { error: FetchBaseQueryError | SerializedError }).error;
      }
      setTokenDetail(response);
      reset();
      setIpAccessControlRules([]);
      onNewTokenFormClose();
      onSecretModalToggle();
    } catch (error) {
      dispatch(newNotification('Failed to create a new token', ErrorMessageParser.parse(error), 'error'));
    }
  };

  return (
    <>
      <Popover placement="bottom" isOpen={isNewTokenFormOpen} onClose={onNewTokenFormClose}>
        <PopoverTrigger>
          <Button
            size="sm"
            mr={4}
            rightIcon={<IoMdArrowDropdown />}
            colorScheme="teal"
            onClick={onNewTokenFormToggle}
          >
            New Token
          </Button>
        </PopoverTrigger>
        <PopoverContent minWidth="max-content" maxW="2xl">
          <PopoverHeader pt={4} fontWeight="bold" border={0} mb={3}>
            Create a new token
          </PopoverHeader>
          <PopoverArrow />
          <PopoverCloseButton />
          <form onSubmit={handleSubmit(onSubmit)}>
            <PopoverBody minWidth="md" maxH="500px" overflowY="auto">
              <VStack spacing={4} align="stretch">
                <FormControl isInvalid={errors.appId ? true : false} isRequired>
                  <FormLabel>Application ID</FormLabel>
                  <Input
                    type="text"
                    placeholder="my-app-id"
                    {...register('appId', { pattern: APP_ID_PATTERN })}
                  />
                  <FormHelperText pl={1}>Register the token with a project before accessing it.</FormHelperText>
                  {errors.appId && (
                    <FormErrorMessage>The first/last character must be alphanumeric</FormErrorMessage>
                  )}
                </FormControl>
                {user.roles.includes('LEVEL_SYSTEM_ADMIN') && (
                  <Flex>
                    <Spacer />
                    <Checkbox colorScheme="teal" {...register('isSystemAdmin')}>
                      System Administrator-Level Token
                    </Checkbox>
                  </Flex>
                )}
                <IpAccessControlForm rules={ipAccessControlRules} onChange={setIpAccessControlRules} />
              </VStack>
            </PopoverBody>
            <PopoverFooter border="0" display="flex" alignItems="center" justifyContent="space-between" pb={4}>
              <Spacer />
              <Button
                type="submit"
                colorScheme="teal"
                variant="ghost"
                isLoading={isLoading}
                loadingText="Creating"
              >
                Create
              </Button>
            </PopoverFooter>
          </form>
        </PopoverContent>
      </Popover>
      <DisplaySecretModal isOpen={isSecretModalOpen} onClose={onSecretModalClose} response={tokenDetail} />
    </>
  );
};
