# -*- coding: utf-8 -*-
# Copyright 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.:w


import threading
import unittest2 as unittest

from mock import Mock, patch

from taskthread import TaskThread, TaskInProcessException, TimerTask

forever_event = threading.Event()


def forever_function(*args, **kwargs):
    forever_event.wait()
    forever_event.clear()


class TaskThreadTestCase(unittest.TestCase):
    """
    Tests for :py:class:`.TaskThread`.
    """

    def test___init__(self):
        """
        Test the __init__ method. It doesn't really do much.
        """
        task_thread = TaskThread(forever_function)
        self.assertEqual(forever_function, task_thread.task)

    def test_run_not_running(self):
        """
        Verifies that thread will shut down when running is false
        """
        event = Mock()
        event.wait = Mock(side_effect=[True])
        event.clear = Mock(side_effect=Exception("Should never be called"))
        task_thread = TaskThread(forever_function,
                                 event=event)
        task_thread.running = False
        task_thread.run()
        event.wait.assert_called_once_with()

    def test_run_executes_task(self):
        event = Mock()
        event.wait = Mock(side_effect=[True, True])

        def stop_iteration(*args, **kwargs):
            args[0].running = False

        task_thread = TaskThread(stop_iteration,
                                 event=event)

        task_thread.args = [task_thread]
        task_thread.kwargs = {'a': 2}
        task_thread.in_task = True
        task_thread.run()
        self.assertEqual(False, task_thread.in_task)

    def test_run_task(self):
        event = Mock()
        task_thread = TaskThread(forever_function,
                                 event=event)
        args = [1]
        kwargs = {'a': 1}

        task_thread.run_task(*args, **kwargs)
        self.assertEqual(tuple(args), task_thread.args)
        self.assertEqual(kwargs, task_thread.kwargs)
        event.set.assert_called_once_with()

    def test_run_task_task_in_progress(self):
        event = Mock()
        task_thread = TaskThread(forever_function,
                                 event=event)
        task_thread.in_task = True
        self.assertRaises(TaskInProcessException, task_thread.run_task)

    def test_join_task(self):
        task_thread = TaskThread(forever_function)
        task_thread.in_task = True
        task_thread.task_complete = Mock()
        task_thread.task_complete.wait = Mock(side_effect=[True])
        success = task_thread.join_task(1)
        self.assertTrue(success)

    def test_join_task_not_running(self):
        task_thread = TaskThread(forever_function)
        task_thread.task_complete = Mock()
        task_thread.wait =\
            Mock(side_effect=Exception("Should never be called"))
        task_thread.join_task(1)

    def test_join(self):
        task_thread = TaskThread(forever_function)
        task_thread.start()
        task_thread.run_task()
        # Set the event so the task completes
        forever_event.set()
        task_thread.join_task(1)
        task_thread.join(1)

    def test_execute_multiple_tasks(self):
        task_thread = TaskThread(forever_function)
        task_thread.start()
        task_thread.run_task()
        # Set the event so the task completes
        forever_event.set()
        task_thread.join_task(1)
        forever_event.set()
        task_thread.join_task(1)
        task_thread.join(1)


def my_func():
    pass


class TimerTaskTestCase(unittest.TestCase):

    def test___int__(self):

        task = TimerTask(my_func,
                         delay=100)
        self.assertEqual(my_func, task.execute_fcn)
        self.assertEqual(100, task.delay)
        self.assertIsNone(task.count_fcn)
        self.assertIsNone(task.threshold)

    def test___int__raises(self):
        self.assertRaises(ValueError, TimerTask.__init__,
                          TimerTask(None),
                          my_func(),
                          count_fcn=Mock())

        self.assertRaises(ValueError, TimerTask.__init__,
                          TimerTask(None),
                          my_func(),
                          threshold=Mock())

    @patch('taskthread.TaskThread')
    def test_start(self, TaskThreadMock):
        task = TimerTask(my_func)
        thread = TaskThreadMock.return_value

        task.start()
        self.assertTrue(task.running)
        self.assertEqual(thread, task.thread)
        thread.start.assert_called_once_with()
        thread.run_task.assert_called_once_with()

    @patch('taskthread.TaskThread')
    def test_start_restarts(self, TaskThreadMock):
        task = TimerTask(my_func, threshold=1, count_fcn=Mock())
        thread = TaskThreadMock.return_value
        task.last_count = 1
        task.thread = thread

        task.start()
        self.assertEqual(0, task.last_count)
        self.assertEqual(0, thread.start.called)
        thread.run_task.assert_called_once_with()

    @patch('taskthread.TaskThread')
    def test_stop(self, TaskThreadMock):
        running_lock = Mock()
        running_lock.__enter__ = Mock()
        running_lock.__exit__ = Mock()
        task = TimerTask(my_func)
        task.thread = TaskThreadMock.return_value
        task.running = True
        task.event = Mock()
        task.running_lock = running_lock

        task.stop()

        self.assertEqual(False, task.running)
        self.assertEqual(1, task.event.set.called)
        running_lock.__enter__.assert_called_once_with()
        running_lock.__exit__.assert_called_once_with(None, None, None)
        task.thread.join_task.assert_called_once_with(2)

    @patch('taskthread.TaskThread')
    def test_stop_not_running(self, TaskThreadMock):
        task = TimerTask(my_func)
        task.thread = TaskThreadMock.return_value
        task.running = False
        task.event = Mock()

        task.stop()

        self.assertEqual(False, task.running)
        self.assertEqual(0, task.event.set.called)
        self.assertEqual(0, task.thread.join_task.called)

    @patch('taskthread.TaskThread')
    def test_shutdown(self, TaskThreadMock):
        task = TimerTask(my_func)
        task.thread = TaskThreadMock.return_value
        task.running = False
        task.shutdown()
        task.thread.join.assert_called_once_with(2)

    def test__exec_if_threshold_met(self):
        self.called = False

        def exec_fcn():
            self.called = True

        def count_fcn():
            return 10

        task = TimerTask(exec_fcn, count_fcn=count_fcn, threshold=1)
        task.last_count = 9
        task._exec_if_threshold_met()
        self.assertTrue(self.called)
        self.assertEqual(10, task.last_count)

    def test__exec_if_threshold_met_not_met(self):

        def exec_fcn():
            raise Exception("This shouldn't happen!!")

        def count_fcn():
            return 10

        task = TimerTask(exec_fcn, count_fcn=count_fcn, threshold=10)
        task.last_count = 9
        task._exec_if_threshold_met()
        self.assertEqual(9, task.last_count)

    def test__exec(self):
        self.called = False

        def exec_fcn():
            self.called = True

        task = TimerTask(exec_fcn)
        task._exec()
        self.assertTrue(self.called)

    def test__exec_threshold(self):
        self.called = False

        def exec_fcn():
            self.called = True

        def count_fcn():
            return 1

        task = TimerTask(exec_fcn, count_fcn=count_fcn, threshold=1)
        task._exec()
        self.assertTrue(self.called)

    @patch('threading.Event')
    def test__wait(self, event_mock):
        task = TimerTask(my_func)
        event = event_mock.return_value

        task._wait()
        event.wait.assert_called_once_with(timeout=task.delay)
        self.assertEqual(1, event.clear.called)

    @patch('threading.RLock')
    def test__exit_loop(self, mock_rlock):
        task = TimerTask(my_func)
        task.running = False
        lock = mock_rlock.return_value
        lock.__enter__ = Mock()
        lock.__exit__ = Mock()
        self.assertTrue(task._exit_loop())
        self.assertEqual(1, lock.__enter__.called)
        lock.__exit__.assert_called_once_with(None, None, None)

    @patch('threading.RLock')
    def test__exit_loop_running(self, mock_rlock):
        lock = mock_rlock.return_value
        lock.__enter__ = Mock()
        lock.__exit__ = Mock()
        task = TimerTask(my_func)
        task.running = True
        self.assertFalse(task._exit_loop())
        self.assertEqual(1, lock.__enter__.called)
        lock.__exit__.assert_called_once_with(None, None, None)

    @patch('threading.RLock')
    @patch('threading.Event')
    def test__run_threshold_timer(self, event_mock, rlock_mock):
        self.task = None
        event = event_mock.return_value
        lock = rlock_mock.return_value
        lock.__enter__ = Mock()
        lock.__exit__ = Mock()

        def exec_fcn():
            self.task.running = False

        self.task = TimerTask(exec_fcn)
        self.task._run_threshold_timer()

        self.assertFalse(self.task.running)
        self.assertEqual(2, event.wait.call_count)
