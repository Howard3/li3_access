<?php

namespace li3_access\extensions\adapter\security\access;

use lithium\core\ConfigException;
use lithium\util\Set;

class Permissions extends \lithium\core\Object {
	const PATH_ROUTE = 'route';
	const PATH_CUSTOM = 'custom';
	const PATH_GROUPS = 'groups';
	const PATH_USERS = 'users';

	const TYPE_USER = 0;
	const TYPE_GROUP = 1;

	protected $_model = array();
	protected $_handlers = array();
	protected $_autoConfig = array('model', 'handlers');

	public function __construct(array $config = array()) {
		$defaults = array(
			'model' => 'app\models\perms',
			'defaultNoUser' => array(),
			'defaultUser' => array(),
			'userIdentifier' => 'id'
		);
		parent::__construct($config + $defaults);
		$this->_handlers += array(
			'serialize' => function($data) {
				return serialize($data);
			},
			'unserialize' => function($data) {
				return unserialize($data);
			}
		);
	}

	/**
	 * @throws \lithium\core\ConfigException
	 * @param  $user
	 * @param  $request
	 * @param array $options
	 * @param null $type constant, TYPE_USER, TYPE_GROUP for example
	 * @return mixed
	 */
	public function check($user, $request, array $options = array(), $type = null) {
		$config = $this->_config;
		$model = $this->_model;
		$handlers = $this->_handlers;
		$params = compact('user', 'request', 'options', 'type');
		return $this->_filter(__METHOD__, $params,
			function($self, $params) use($config, $model, $handlers) {
				$user = $params['user'];
				$request = $params['request'];
				$options = $params['options'];
				$type = $params['type'];
				$reqIsObject = is_object($request);
				$path = array();

				if (!$type) {
					$type = Permissions::TYPE_USER;
				}

				switch (true) {
					case $reqIsObject:
						$path = array(
							Permissions::PATH_ROUTE,
							$request->controller,
							$request->action
						);
						break;
					case (!$reqIsObject && is_string($request)):
						$path = explode('.', $request);
						array_unshift($path, Permissions::PATH_CUSTOM);
						break;
					case (!$reqIsObject && is_array($request)):
						$path = $request;
						break;
				}
				$userId = $config['userIdentifier'];
				switch (true) {
					case !$user || (is_array($user) && !isset($user[$userId])):
						$hasAccess = $self->_processPath($path, $config['defaultNoUser']);
						return $hasAccess ? false : $options;
					case ($result = $self->_processPath($path, $config['defaultUser'])):
						return $result ? false : $options;
					default:
						if (is_scalar($user)) {
							$user = array($userId => $user);
						}
						$perms = $model::find('first', array(
								'conditions' => array(
									'id' => $user[$userId],
									'type' => $type
								)
							));
						if (!$perms) {
							return $options;
						}
						$perms = $perms->data();
						$userPath = $handlers['unserialize']($perms['perms']);
						$PATH_USERS = Permissions::PATH_USERS;
						$PATH_GROUPS = Permissions::PATH_GROUPS;
						$TYPE_GROUP = Permissions::TYPE_GROUP;
						$result = $self->_processPath($path, $userPath);
						$userHasGroups = isset($userPath[$PATH_GROUPS]);
						if ($result || $type == $TYPE_GROUP || !$userHasGroups) {
							$result = $result ? array() : $options;
							if ($type != $TYPE_GROUP || $result) {
								return $result;
							}
							if (!in_array($options['forUser'][$userId], $userPath[$PATH_USERS])) {
								return $options;
							}
							return $result;
						}
						$options['forUser'] = $user;
						foreach ($userPath[$PATH_GROUPS] as $group) {
							$result = $self->check($group, $path, $options,
								$TYPE_GROUP);
							if (!$result) {
								break;
							}
						}
						return $result;
				}
			});
	}

	public function addUserToGroup($user, $group) {
		$userId = $user[$this->_config['userIdentifier']];
		$user = $this->add($user, array(self::PATH_GROUPS => array($group)), self::TYPE_USER);
		$group = $this->add($group, array(self::PATH_USERS => array($userId)), self::TYPE_GROUP);
		return $user && $group;
	}

	public function removeUserFromGroup($user, $group) {
		$userId = $user[$this->_config['userIdentifier']];
		$user = $this->remove($user, array(self::PATH_GROUPS => array($group)), self::TYPE_USER);
		$grp = $this->remove($group, array(self::PATH_USERS => array($userId)), self::TYPE_GROUP);
		return $user && $grp;
	}

	/**
	 * Adds a group that can later have permissions added to it.
	 * @param $name the name of the group to be added
	 * @return bool
	 */
	public function createGroup($name) {
		$model = $this->_model;
		$handlers = $this->_handlers;
		$perms = $model::create(array(
				'id' => $name,
				'perms' => $handlers['serialize'](array()),
				'type' => self::TYPE_GROUP
			));
		return $perms->save();
	}

	public function removeGroup($name) {
		return $this->removeRow($name, self::TYPE_GROUP);
	}

	public function removeUser($user) {
		$userId = $this->_config['userIdentifier'];
		return !isset($user[$userId]) ? false : $this->removeRow($user[$userId], self::TYPE_USER);
	}

	public function removeRow($id, $type = null) {
		$model = $this->_model;
		$params = compact('id', 'type');
		return $this->_filter(__METHOD__, $params, function($self, $params) use ($model) {
				$id = $params['id'];
				$type = $params['type'];
				if (is_null($type)) {
					return false;
				}
				$result = $model::find('first', array(
						'conditions' => array(
							'id' => $id,
							'type' => $type
						)
					));
				if (!$result) {
					return false;
				}
				return $result->delete();
			});
	}

	/**
	 * Convenience function, forwards the addAction method.
	 */
	public function groupAddAction($name, $controller, $action) {
		return $this->addAction($name, $controller, $action, self::TYPE_GROUP);
	}

	/**
	 * Convenience function, forwards the addCustomPath method.
	 */
	public function groupAddCustomPath($name, $customRoute) {
		return $this->addCustomPath($name, $customRoute, self::TYPE_GROUP);
	}

	/**
	 * Convenience function, forwards the add method.
	 */
	public function groupAdd($name, $paths) {
		return $this->add($name, $paths, self::TYPE_GROUP);
	}

	/**
	 * Convenience function, forwards the addAction method.
	 */
	public function groupRemoveAction($name, $controller, $action) {
		return $this->removeAction($name, $controller, $action, self::TYPE_GROUP);
	}

	/**
	 * Convenience function, forwards the addCustomPath method.
	 */
	public function groupRemoveCustomPath($name, $customRoute) {
		return $this->removeCustomPath($name, $customRoute, self::TYPE_GROUP);
	}

	/**
	 * Convenience function, forwards the add method.
	 */
	public function groupRemove($name, $paths) {
		return $this->remove($name, $paths, self::TYPE_GROUP);
	}

	/**
	 * Adds a custom route to the users permission list.
	 *
	 * $customRoute is formatted as a dot path string, this is done as 'foo.bar.baz' for example.
	 * Asterisks are usable at the end of the path however not in the middle. A user with access
	 * to 'foo.bar.*' will have access to foo.bar.baz, foo.bar.aaa etc.
	 *
	 * @param  $user
	 * @param  $customRoute
	 * @return bool
	 */
	public function addCustomPath($user, $customRoute, $type = null) {
		if (!is_string($customRoute)) {
			return false;
		}
		$parts = explode('.', $customRoute);
		$value = array_pop($parts);
		$parts = array_merge((array)self::PATH_CUSTOM, $parts, (array)0);
		return $this->add($user, Set::expand(array(implode('.', $parts) => $value)), $type);
	}

	/**
	 * Adds an action to the users permission list. If the action is set to * the user will have
	 * access to all of the controllers actions.
	 */
	public function addAction($user, $controller, $action, $type = null) {
		$path = array(
			self::PATH_ROUTE => array(
				$controller => array(
					$action
				)
			)
		);
		return $this->add($user, $path, $type);
	}

	/**
	 * $user must contain the 'userIdentifier' key defined in config
	 * $paths are the paths which are to be added this is an array representation of the path and
	 * is from the origin, so 'route' or 'custom' must be specified. Multiple paths can be defined
	 * using this function
	 *
	 * @throws \lithium\core\ConfigException
	 * @param  $user
	 * @param array $paths
	 * @param int $type
	 * @return bool
	 */
	public function add($user, array $paths = array(), $type = null) {
		$model = $this->_model;
		$handlers = $this->_handlers;
		$userId = $this->_config['userIdentifier'];
		$params = compact('user', 'paths', 'type');
		return $this->_filter(__METHOD__, $params,
			function($self, $params) use ($model, $userId, $handlers) {
				$user = $params['user'];
				$paths = $params['paths'];
				$type = $params['type'];

				if (is_scalar($user)) {
					$user = array($userId => $user);
				}

				if (!$type) {
					$type = Permissions::TYPE_USER;
				}

				if (!isset($user[$userId])) {
					throw new ConfigException("The user identifier '{$userId}' is not available.");
				}
				$result = $model::find('first', array(
						'conditions' => array(
							'id' => $user[$userId],
							'type' => $type
						)
					));
				if (!$result) {
					$perms = $model::create(array(
							'id' => (string)$user[$userId],
							'perms' => $handlers['serialize']($paths),
							'type' => $type
						));
					return $perms->save();
				}
				$resultData = $result->data();
				$allowedPaths = (array)$handlers['unserialize']($resultData['perms']);
				$allowedPaths = array_merge_recursive($allowedPaths, $paths);
				$allowedPaths = $self->unique($allowedPaths);
				$result->perms = $handlers['serialize']($allowedPaths);
				return $result->save();
			});
	}

	public function removeCustomPath($user, $customRoute, $type = null) {
		if (!is_string($customRoute)) {
			return false;
		}
		$parts = explode('.', $customRoute);
		$value = array_pop($parts);
		$parts = array_merge((array)self::PATH_CUSTOM, $parts, (array)0);
		return $this->remove($user, Set::expand(array(implode('.', $parts) => $value)), $type);
	}

	/**
	 * Removes an action from a users permission list. Setting action to * removes all actions
	 * in the controller thus removing the controller from the users permission list.
	 */
	public function removeAction($user, $controller, $action, $type = null) {
		$path = array(
			self::PATH_ROUTE => array(
				$controller => array(
					$action
				)
			)
		);
		return $this->remove($user, $path, $type);
	}

	/**
	 * use this to remove permissions from a user, multiple permissions can be defined in the paths
	 * array. The user must have the configured userIdentifier available.
	 *
	 * @throws \lithium\core\ConfigException
	 * @param  $user
	 * @param array $paths
	 * @param int $type
	 * @return bool
	 */
	public function remove($user, array $paths = array(), $type = null) {
		if (!$type) {
			$type = self::TYPE_USER;
		}
		$model = $this->_model;
		$handlers = $this->_handlers;
		$userId = $this->_config['userIdentifier'];
		$params = compact('user', 'paths', 'type');
		return $this->_filter(__METHOD__, $params,
			function($self, $params) use ($model, $userId, $handlers) {
				$user = $params['user'];
				$paths = $params['paths'];
				$type = $params['type'];

				if (is_scalar($user)) {
					$user = array($userId => $user);
				}

				if (!isset($user[$userId])) {
					throw new ConfigException("The user identifier '{$userId}' is not available.");
				}
				$result = $model::find('first', array(
						'conditions' => array(
							'id' => (string)$user[$userId],
							'type' => $type
						)
					));
				if (!$result) {
					return true;
				}
				$allowedPaths = $result->perms;
				if (is_object($allowedPaths) && method_exists($allowedPaths, 'data')) {
					$allowedPaths = $allowedPaths->data();
				}
				$allowedPaths = $handlers['unserialize']($allowedPaths);
				$pathsFlat = Set::flatten($paths);
				foreach ($pathsFlat as $path => $value) {
					$pointer = &$allowedPaths;
					$pathParts = explode('.', $path);
					foreach ($pathParts as $pathPart) {
						if (!isset($pointer[$pathPart])) {
							unset($pointer);
							$pointer = null;
							break;
						}
						$pointer = &$pointer[$pathPart];
					}
					$pointer = (array)$pointer;
					switch (true) {
						case !$pointer:
							break;
						case $value == '*':
							$pointer = null;
							break;
						case (($index = array_search($value, $pointer)) !== false):
							unset($pointer[$index]);
							break;
					}
				}
				$result->perms = $handlers['serialize']($self->_cleanPaths($allowedPaths));
				return $result->save();
			});
	}

	public function listPerms($user, $type = null) {
		if (!$type) {
			$type = self::TYPE_USER;
		}
		$userId = $user[$this->_config['userIdentifier']];
		$model = $this->_model;
		$handlers = $this->_handlers;
		$result = $model::find('first', array(
				'conditions' => array(
					'id' => $userId,
					'type' => $type
				)
			));
		return $result ? $handlers['unserialize']($result->perms) : array();
	}

	public function _cleanPaths($paths) {
		foreach ($paths as &$path) {
			if (is_array($path)) {
				$path = $this->_cleanPaths($path);
			}
		}
		return array_filter($paths);
	}

	public function _processPath($path, &$allowedPaths) {
		$pointer = &$allowedPaths;
		foreach ($path as $item) {
			switch (true) {
				case (in_array('*', $pointer)):
					return true;
				case (in_array($item, $pointer)):
					$pointer = array();
					continue;
				case (!isset($pointer[$item])):
					return false;
			}
			$pointer = &$pointer[$item];
		}
		return true;
	}

	public function unique($array) {
		$output = array();
		foreach ($array as $key => $element) {
			if (is_array($element)) {
				$output[$key] = $this->unique($element);
				continue;
			}
			if (!in_array($element, $output)) {
				$output[$key] = $element;
			}
		}
		return $output;
	}
}

?>