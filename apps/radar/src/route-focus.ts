let routeFocusRequested = false;

export const requestRouteFocus = () => {
  routeFocusRequested = true;
};

export const consumeRouteFocus = () => {
  const requested = routeFocusRequested;
  routeFocusRequested = false;
  return requested;
};
