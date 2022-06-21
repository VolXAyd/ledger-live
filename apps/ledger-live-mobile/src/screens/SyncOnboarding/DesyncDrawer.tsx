import React, { useCallback } from "react";
import { BottomDrawer, Button, Link, Text } from "@ledgerhq/native-ui";
import { ExternalLinkMedium } from "@ledgerhq/native-ui/assets/icons";

export type Props = {
  isOpen: boolean;
  onClose?: () => void;
};

const DesyncDrawer = ({ isOpen, onClose }: Props) => {
  const handleDocumentationPress = useCallback(() => {
    // TODO: add logic when user press "FAQ" button
  }, []);

  const handleSupportPress = useCallback(() => {
    // TODO: add logic when user press "Support" button
  }, []);

  return (
    <BottomDrawer onClose={onClose} isOpen={isOpen}>
      <Text variant="h4" textAlign="center" mb={4}>
        We could not connect to your Nano
      </Text>
      <Text variant="body" textAlign="center" mb={8} color="neutral.c80">
        Please make sure your Nano is nearby and unlocked. Check to see if
        Bluetooth is enabled on your mobile phone
      </Text>
      <Button type="main" outline mb={6} onPress={handleDocumentationPress}>
        Try again
      </Button>
      <Link Icon={ExternalLinkMedium} onPress={handleSupportPress}>
        Get help
      </Link>
    </BottomDrawer>
  );
};

export default DesyncDrawer;