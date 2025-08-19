/*
 * Copyright 2025 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

import React, { useState } from 'react';
import {
  Box,
  Button,
  FormControl,
  FormLabel,
  Input,
  Select,
  VStack,
  HStack,
  Text,
  IconButton,
  Card,
  CardBody,
  Alert,
  AlertIcon,
  Badge,
} from '@chakra-ui/react';
import { AddIcon, DeleteIcon } from '@chakra-ui/icons';
import { IpAccessControlRule } from './TokenDto';

interface IpAccessControlFormProps {
  rules: IpAccessControlRule[];
  onChange: (rules: IpAccessControlRule[]) => void;
  isDisabled?: boolean;
}

const IpAccessControlForm: React.FC<IpAccessControlFormProps> = ({ rules, onChange, isDisabled = false }) => {
  const [newRule, setNewRule] = useState<IpAccessControlRule>({
    action: 'ALLOW',
    cidr: '',
    description: '',
  });

  const [cidrError, setCidrError] = useState<string>('');

  const validateCidr = (cidr: string): boolean => {
    if (!cidr.trim()) return false;

    // Basic CIDR validation - supports both IPv4 and IPv6
    const cidrRegex =
      /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$|^::1(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$|^::(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$/;

    // Also accept single IP addresses without CIDR notation
    const ipv4Regex =
      /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;

    return cidrRegex.test(cidr) || ipv4Regex.test(cidr) || ipv6Regex.test(cidr);
  };

  const handleAddRule = () => {
    if (!validateCidr(newRule.cidr)) {
      setCidrError('Invalid CIDR notation. Examples: 192.168.1.0/24, 10.0.0.1/32, 192.168.1.1');
      return;
    }

    setCidrError('');
    onChange([...rules, { ...newRule, description: newRule.description || undefined }]);
    setNewRule({ action: 'ALLOW', cidr: '', description: '' });
  };

  const handleRemoveRule = (index: number) => {
    onChange(rules.filter((_, i) => i !== index));
  };

  const handleRuleChange = (index: number, field: keyof IpAccessControlRule, value: string) => {
    const updatedRules = rules.map((rule, i) =>
      i === index ? { ...rule, [field]: value || undefined } : rule,
    );
    onChange(updatedRules);
  };

  return (
    <VStack spacing={4} align="stretch">
      <Box>
        <FormLabel fontWeight="bold">IP Access Control Rules</FormLabel>
        <Text fontSize="sm" color="gray.600" mb={3}>
          Control which IP addresses can use this token. Rules are evaluated in order, and the first matching
          rule determines access. If no rules match, access is allowed by default.
        </Text>
      </Box>

      {/* Existing Rules */}
      {rules.length > 0 && (
        <VStack spacing={3} align="stretch">
          {rules.map((rule, index) => (
            <Card key={index} size="sm">
              <CardBody>
                <HStack spacing={3} align="start">
                  <Badge
                    colorScheme={rule.action === 'ALLOW' ? 'green' : 'red'}
                    variant="solid"
                    minW="60px"
                    textAlign="center"
                  >
                    {rule.action}
                  </Badge>
                  <VStack flex={1} spacing={2} align="stretch">
                    <Input
                      value={rule.cidr}
                      onChange={(e) => handleRuleChange(index, 'cidr', e.target.value)}
                      placeholder="CIDR (e.g., 192.168.1.0/24)"
                      isDisabled={isDisabled}
                      size="sm"
                    />
                    <Input
                      value={rule.description || ''}
                      onChange={(e) => handleRuleChange(index, 'description', e.target.value)}
                      placeholder="Optional description"
                      isDisabled={isDisabled}
                      size="sm"
                    />
                  </VStack>
                  <IconButton
                    aria-label="Remove rule"
                    icon={<DeleteIcon />}
                    onClick={() => handleRemoveRule(index)}
                    isDisabled={isDisabled}
                    colorScheme="red"
                    variant="ghost"
                    size="sm"
                  />
                </HStack>
              </CardBody>
            </Card>
          ))}
        </VStack>
      )}

      {/* Add New Rule Form */}
      {!isDisabled && (
        <Card>
          <CardBody>
            <VStack spacing={3}>
              <HStack spacing={3} align="end" w="full">
                <FormControl w="120px">
                  <FormLabel fontSize="sm">Action</FormLabel>
                  <Select
                    value={newRule.action}
                    onChange={(e) => setNewRule({ ...newRule, action: e.target.value as 'ALLOW' | 'DENY' })}
                    size="sm"
                  >
                    <option value="ALLOW">ALLOW</option>
                    <option value="DENY">DENY</option>
                  </Select>
                </FormControl>
                <FormControl flex={1}>
                  <FormLabel fontSize="sm">CIDR</FormLabel>
                  <Input
                    value={newRule.cidr}
                    onChange={(e) => {
                      setNewRule({ ...newRule, cidr: e.target.value });
                      setCidrError('');
                    }}
                    placeholder="e.g., 192.168.1.0/24, 10.0.0.1/32, or single IP"
                    isInvalid={!!cidrError}
                    size="sm"
                  />
                </FormControl>
                <Button
                  leftIcon={<AddIcon />}
                  onClick={handleAddRule}
                  colorScheme="blue"
                  size="sm"
                  isDisabled={!newRule.cidr.trim()}
                >
                  Add Rule
                </Button>
              </HStack>
              <FormControl>
                <FormLabel fontSize="sm">Description (optional)</FormLabel>
                <Input
                  value={newRule.description}
                  onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                  placeholder="Describe this rule"
                  size="sm"
                />
              </FormControl>
              {cidrError && (
                <Alert status="error" size="sm">
                  <AlertIcon />
                  {cidrError}
                </Alert>
              )}
            </VStack>
          </CardBody>
        </Card>
      )}

      {rules.length === 0 && (
        <Alert status="info" size="sm">
          <AlertIcon />
          No IP restrictions configured. This token can be used from any IP address.
        </Alert>
      )}
    </VStack>
  );
};

export default IpAccessControlForm;
